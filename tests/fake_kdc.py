#!/usr/bin/env python3
"""Scripted KDC for roastwatch tests and demo runs.

Speaks just enough RFC 4120 on 127.0.0.1 to exercise the client's crypto
and error paths against known keys. This is fixture data with a socket on
it, not a real KDC, and it never touches the network beyond loopback.
"""

import socket
import struct
import threading

import roastwatch as rw

REALM = "CORP.LOCAL"

# NT hash of the password 'password', a published example hash.
NT_HASH_JDOE = bytes.fromhex("8846f7eaee8fb117ad06bdd830b7586c")
SESSION_KEY = bytes(range(16))

# Fixed ciphertext fixtures for hash emission (structure only, not real
# encrypted material).
ASREP_CIPHER = bytes(range(16)) + b"\x5a" * 20
TGS_CIPHER_RC4 = bytes(range(16)) + b"\x77" * 24
TGS_CIPHER_AES = bytes(range(32)) + b"\x66" * 12

ASREP_USERS = ("svc-backup",)      # answered without pre-auth
UNKNOWN_USERS = ("ghost",)
PREAUTH_USERS = ("haspreauth",)
UNKNOWN_SPNS = ("BADSPN/nope",)
AES_ONLY_SPNS = ("AESVC/host.corp.local",)


def krb_error(code, etext=None):
    parts = [
        rw.enc_ctx(0, rw.enc_int(5)),
        rw.enc_ctx(1, rw.enc_int(30)),
        rw.enc_ctx(4, rw.enc_gstr(rw.kerberos_time())),
        rw.enc_ctx(5, rw.enc_int(0)),
        rw.enc_ctx(6, rw.enc_int(code)),
    ]
    if etext:
        parts.append(rw.enc_ctx(11, rw.enc_gstr(etext)))
    return rw.enc_app(30, rw.enc_seq(*parts))


def ticket(cname, realm=REALM, cipher=b"\xaa" * 32):
    return rw.enc_app(1, rw.enc_seq(
        rw.enc_ctx(0, rw.enc_int(5)),
        rw.enc_ctx(1, rw.enc_gstr(realm)),
        rw.enc_ctx(2, rw.enc_princ(2, [cname])),
        rw.enc_ctx(3, rw.enc_seq(rw.enc_ctx(0, rw.enc_int(23)),
                                 rw.enc_ctx(2, rw.enc_octet(cipher)))),
    ))


def as_rep(cname, etype, cipher, realm=REALM):
    return rw.enc_app(11, rw.enc_seq(
        rw.enc_ctx(0, rw.enc_int(5)),
        rw.enc_ctx(1, rw.enc_int(11)),
        rw.enc_ctx(3, rw.enc_gstr(realm)),
        rw.enc_ctx(4, rw.enc_princ(1, [cname])),
        ticket("krbtgt/" + realm.lower(), realm),
        rw.enc_ctx(6, rw.enc_seq(rw.enc_ctx(0, rw.enc_int(etype)),
                                 rw.enc_ctx(2, rw.enc_octet(cipher)))),
    ))


def tgs_rep(cname, etype, cipher, realm=REALM):
    return rw.enc_app(13, rw.enc_seq(
        rw.enc_ctx(0, rw.enc_int(5)),
        rw.enc_ctx(1, rw.enc_int(13)),
        rw.enc_ctx(3, rw.enc_gstr(realm)),
        rw.enc_ctx(4, rw.enc_princ(1, [cname])),
        ticket(cname, realm),
        rw.enc_ctx(6, rw.enc_seq(rw.enc_ctx(0, rw.enc_int(etype)),
                                 rw.enc_ctx(2, rw.enc_octet(cipher)))),
    ))


def enc_as_rep_part(session_etype, session_key, realm=REALM):
    return rw.enc_app(25, rw.enc_seq(
        rw.enc_ctx(0, rw.enc_seq(rw.enc_ctx(0, rw.enc_int(session_etype)),
                                 rw.enc_ctx(1, rw.enc_octet(session_key)))),
        rw.enc_ctx(1, rw.enc_seq(rw.enc_ctx(0, rw.enc_int(0)),
                                 rw.enc_ctx(1, rw.enc_gstr(rw.kerberos_time())))),
        rw.enc_ctx(2, rw.enc_int(12345)),
        rw.enc_ctx(5, rw.enc_gstr(rw.kerberos_time())),
        rw.enc_ctx(7, rw.enc_gstr(rw.kerberos_time())),
        rw.enc_ctx(9, rw.enc_gstr(realm)),
        rw.enc_ctx(10, rw.enc_princ(2, ["krbtgt", realm])),
    ))


class FakeKDC(threading.Thread):
    daemon = True

    def __init__(self, realm=REALM):
        super().__init__()
        self.realm = realm
        self.stop_flag = False
        self.last_error = None
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(5)
        self.udp_port = self.udp.getsockname()[1]
        self.tcp_port = self.tcp.getsockname()[1]

    def run(self):
        t = threading.Thread(target=self._serve_udp, daemon=True)
        t.start()
        while not self.stop_flag:
            self.tcp.settimeout(0.2)
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._serve_tcp_conn(conn)
        t.join(timeout=1)

    def stop(self):
        self.stop_flag = True
        for s in (self.udp, self.tcp):
            try:
                s.close()
            except OSError:
                pass

    def _serve_udp(self):
        while not self.stop_flag:
            self.udp.settimeout(0.2)
            try:
                data, addr = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            reply = self.dispatch(data)
            if reply:
                self.udp.sendto(reply, addr)

    def _serve_tcp_conn(self, conn):
        conn.settimeout(2)
        try:
            head = b""
            while len(head) < 4:
                chunk = conn.recv(4 - len(head))
                if not chunk:
                    return
                head += chunk
            ln = struct.unpack(">I", head)[0]
            body = b""
            while len(body) < ln:
                chunk = conn.recv(ln - len(body))
                if not chunk:
                    return
                body += chunk
            reply = self.dispatch(body)
            if reply:
                conn.sendall(struct.pack(">I", len(reply)) + reply)
        except OSError:
            pass
        finally:
            conn.close()

    # -- request routing ---------------------------------------------------

    def dispatch(self, data):
        try:
            node = rw.der_decode(data)
            if node.is_app(10):
                return self.handle_asreq(node)
            if node.is_app(12):
                return self.handle_tgsreq(node)
            return krb_error(24, "fake kdc: unexpected application tag")
        except Exception as e:  # surface client-side protocol bugs in etext
            self.last_error = repr(e)
            return krb_error(24, "fake kdc: %r" % e)

    def handle_asreq(self, node):
        node = node.payload()
        body = rw.field(node, 4)
        cname_node = rw.field(body, 1)
        cname = rw.principal_strings(cname_node)[0] if cname_node is not None else None
        padata = rw.field(node, 3)
        if cname in UNKNOWN_USERS:
            return krb_error(6)
        if cname in PREAUTH_USERS:
            return krb_error(25)
        if cname == "svc-backup" and padata is None:
            return as_rep(cname, 23, ASREP_CIPHER, self.realm)
        if cname == "jdoe" and padata is not None:
            pa = padata.kids()[0]
            ptype = rw.field(pa, 1).as_int()
            if ptype != 2:
                return krb_error(24, "fake kdc: expected PA-ENC-TIMESTAMP")
            enc = rw.field(pa, 2).as_bytes()
            rw.rc4_hmac_decrypt(NT_HASH_JDOE, enc, rw.KU_PA_ENC_TIMESTAMP)
            part = enc_as_rep_part(23, SESSION_KEY, self.realm)
            cipher = rw.rc4_hmac_encrypt(NT_HASH_JDOE, part,
                                         rw.KU_AS_REP_ENC_PART)
            return as_rep(cname, 23, cipher, self.realm)
        return krb_error(6)

    def handle_tgsreq(self, node):
        node = node.payload()
        padata = rw.field(node, 3)
        if padata is None:
            return krb_error(24, "fake kdc: TGS-REQ without padata")
        pa = padata.kids()[0]
        if rw.field(pa, 1).as_int() != 1:
            return krb_error(24, "fake kdc: expected PA-TGS-REQ")
        apreq = rw.der_decode(rw.field(pa, 2).as_bytes())
        if not apreq.is_app(14):
            return krb_error(24, "fake kdc: padata is not an AP-REQ")
        ap = apreq.payload()
        auth = rw.field(ap, 4)
        etype = rw.field(auth, 0).as_int()
        if etype != 23:
            return krb_error(24, "fake kdc: authenticator etype %d" % etype)
        try:
            rw.rc4_hmac_decrypt(SESSION_KEY, rw.field(auth, 2).as_bytes(),
                                rw.KU_TGS_AUTHENTICATOR)
        except rw.RoastError as e:
            return krb_error(24, "fake kdc: authenticator %s" % e)
        body = rw.field(node, 4)
        sname = rw.principal_strings(rw.field(body, 3))
        spn = "/".join(sname)
        etypes = [c.as_int() for c in rw.field(body, 8).kids()]
        if spn in UNKNOWN_SPNS:
            return krb_error(7)
        if spn in AES_ONLY_SPNS:
            if etypes == [23]:
                return krb_error(14)
            return tgs_rep("jdoe", 18, TGS_CIPHER_AES, self.realm)
        return tgs_rep("jdoe", 23, TGS_CIPHER_RC4, self.realm)
