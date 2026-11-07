"""roastwatch test suite. Run with: python3 -m unittest discover -s tests -v"""

import json
import os
import subprocess
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import roastwatch as rw  # noqa: E402
from fake_kdc import (  # noqa: E402
    ASREP_CIPHER, FakeKDC, NT_HASH_JDOE, SESSION_KEY, TGS_CIPHER_AES,
    TGS_CIPHER_RC4,
)

TOOL = os.path.join(ROOT, "roastwatch.py")
LDIF = os.path.join(HERE, "fixtures", "users.ldif")
JSON_FIX = os.path.join(HERE, "fixtures", "users.json")

# Hashcat example hashes, copied from hashcat.net/wiki example_hashes.
HC_13100 = ("$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$"
            "891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea5"
            "82ab5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f"
            "2385bb3799d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e"
            "9ad0c20ed53a7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf"
            "35c77de12456bf1144b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8"
            "757312e9e4e6272de35e20d52fb668c5ed")
HC_18200 = ("$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$"
            "007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c75"
            "4d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d"
            "49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483"
            "342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811"
            "a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94"
            "e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc1791"
            "18f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac")
HC_19600 = ("$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$"
            "90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c"
            "86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4a"
            "f037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96"
            "b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace"
            "4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017"
            "459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e")
HC_32100 = ("$krb5asrep$17$user$EXAMPLE.COM$a419c4030e555734b06c2629$"
            "c09a1421f96eb126c757a4b87830381f142477d9a85b2beb3093dbfd44f38ddb601"
            "6a479537fb7b36e046315869fe79187217971ff6a12c1e0a2df3f68045e03814b21"
            "f756d8981f781803d65e8572823c88979581d93cf7d768f2efced16f3719b8d1004"
            "d9e73d798de255383476bced47d1982f16be77d0feb55a1f44f58bd013fa4caee58"
            "ac614caf0f1cf9101ec9623c5b8c2a1491b73f134f074790088fdb360b5ebce0d32"
            "a8145ed00a81ddf77188e150b92d8e8ddd0285d27f1514253e5546e6bba864b362b"
            "b1e6483b26d08fa4cc268bfbefe0f690039bcc524b774599df3680c1c3431d891bf"
            "a99514a877f964e")


def run_cli(args):
    return subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, timeout=60)


class DerTest(unittest.TestCase):
    def test_int_encodings(self):
        self.assertEqual(rw.enc_int(5), bytes.fromhex("020105"))
        self.assertEqual(rw.enc_int(0), bytes.fromhex("020100"))
        self.assertEqual(rw.enc_int(128), bytes.fromhex("02020080"))
        self.assertEqual(rw.enc_int(0x50800000),
                         bytes.fromhex("020450800000"))

    def test_roundtrip(self):
        blob = rw.enc_app(10, rw.enc_seq(
            rw.enc_ctx(1, rw.enc_int(5)),
            rw.enc_ctx(3, rw.enc_seq(rw.enc_ctx(1, rw.enc_int(2)),
                                     rw.enc_ctx(2, rw.enc_octet(b"abc")))),
        ))
        node = rw.der_decode(blob)
        self.assertTrue(node.is_app(10))
        self.assertEqual(rw.field(node.payload(), 1).as_int(), 5)
        inner = rw.field(rw.field(node.payload(), 3), 2)
        self.assertEqual(inner.as_bytes(), b"abc")

    def test_errors(self):
        with self.assertRaises(rw.DerError):
            rw.der_decode(b"\x30\x05\x02\x01")
        with self.assertRaises(rw.DerError):
            rw.der_decode(b"\x30\x02\x01\x00\x00")
        with self.assertRaises(rw.DerError):
            rw.der_decode(b"\x30\x80\x01")


class CryptoTest(unittest.TestCase):
    def test_md4_vectors(self):
        # RFC 1320 appendix test suite
        cases = {
            b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
            b"a": "bde52cb31de33e46245e05fbdbd6fb24",
            b"abc": "a448017aaf21d8525fc10ae87aa6729d",
            b"message digest": "d9130a8164549fe818874806e1c7014b",
            b"abcdefghijklmnopqrstuvwxyz":
                "d79e1c308aa5bbcdeea8ed63df412da9",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
                "043f8582f241db351ce627e153e7f0e4",
            b"12345678901234567890123456789012345678901234567890"
            b"123456789012345678901234567890":
                "e33b4ddc9c38f2199c3e7b164fcc0536",
        }
        for msg, want in cases.items():
            self.assertEqual(rw.md4(msg).hex(), want, msg[:20])

    def test_nt_hash(self):
        self.assertEqual(rw.nt_hash("password").hex(),
                         "8846f7eaee8fb117ad06bdd830b7586c")

    def test_rc4_vectors(self):
        cases = [
            (b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
            (b"Wiki", b"pedia", "1021bf0420"),
            (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
        ]
        for key, plain, want in cases:
            self.assertEqual(rw._xor(rw.RC4(key).stream(len(plain)), plain).hex(),
                             want)

    def test_rc4_hmac_roundtrip(self):
        for usage in (1, 3, 7, 8):
            for key_len in (16, 32):
                key = bytes((i * 37 + 11) % 256 for i in range(key_len))
                data = os.urandom(51)
                self.assertEqual(
                    rw.rc4_hmac_decrypt(key, rw.rc4_hmac_encrypt(key, data, usage),
                                        usage),
                    data, usage)

    def test_rc4_hmac_rejects_corruption(self):
        key = b"k" * 16
        ed = rw.rc4_hmac_encrypt(key, b"hello world", 3)
        bad = ed[:16] + bytes([ed[16] ^ 1]) + ed[17:]
        with self.assertRaises(rw.RoastError):
            rw.rc4_hmac_decrypt(key, bad, 3)

    def test_nthash_parse(self):
        self.assertEqual(rw.parse_nthash("8846F7EAEE8FB117AD06BDD830B7586C"),
                         NT_HASH_JDOE)
        with self.assertRaises(rw.RoastError):
            rw.parse_nthash("xyz")
        with self.assertRaises(rw.RoastError):
            rw.parse_nthash("8846f7eaee8fb117ad06bdd830b7586c00")


class HashcatFormatTest(unittest.TestCase):
    """Round-trip hashcat's own example hashes through our emitters."""

    @staticmethod
    def _tgs_parts(hc):
        parts = hc.split("$")
        mid = "$".join(parts[3:6])
        user, realm, spn = mid[1:-1].split("$")
        cipher = bytes.fromhex(parts[6]) + bytes.fromhex(parts[7])
        return int(parts[2]), user, realm, spn, cipher

    @staticmethod
    def _tgs_aes_parts(hc):
        parts = hc.split("$")
        cipher = bytes.fromhex(parts[6]) + bytes.fromhex(parts[5])
        return int(parts[2]), parts[3], parts[4], cipher

    @staticmethod
    def _asrep_parts(hc):
        parts = hc.split("$")
        ident, first = parts[3].split(":", 1)
        user, realm = ident.split("@", 1)
        cipher = bytes.fromhex(first) + bytes.fromhex(parts[4])
        return int(parts[2]), user, realm, cipher

    @staticmethod
    def _asrep_aes_parts(hc):
        parts = hc.split("$")
        cipher = bytes.fromhex(parts[6]) + bytes.fromhex(parts[5])
        return int(parts[2]), parts[3], parts[4], cipher

    def test_13100_roundtrip(self):
        etype, user, realm, spn, cipher = self._tgs_parts(HC_13100)
        self.assertEqual(rw.emit_tgs_hash(etype, user, realm, spn, cipher),
                         HC_13100)

    def test_18200_roundtrip(self):
        etype, user, realm, cipher = self._asrep_parts(HC_18200)
        self.assertEqual(rw.emit_asrep_hash(etype, user, realm, cipher), HC_18200)

    def test_19600_roundtrip(self):
        etype, user, realm, cipher = self._tgs_aes_parts(HC_19600)
        self.assertEqual(rw.emit_tgs_hash(etype, user, realm, "any/spn", cipher),
                         HC_19600)

    def test_32100_roundtrip(self):
        etype, user, realm, cipher = self._asrep_aes_parts(HC_32100)
        self.assertEqual(rw.emit_asrep_hash(etype, user, realm, cipher), HC_32100)

    def test_32200_shape(self):
        cipher = bytes(range(32)) + b"\x55" * 12
        h = rw.emit_tgs_hash(18, "svc", "R.LOCAL", "x/y", cipher)
        self.assertEqual(h.split("$")[:4], ["", "krb5tgs", "18", "svc"])
        self.assertEqual(h.split("$")[5], cipher[-12:].hex())


class ExportTest(unittest.TestCase):
    def test_ldif_fold_and_base64(self):
        text = ("dn: CN=x,DC=corp,DC=local\n"
                "sAMAccountName: x\n"
                "servicePrincipalName: HTTP/very.long\n"
                " host.example\n"
                "msDS-SupportedEncryptionTypes:: MjQ=\n"
                "\n"
                "dn: CN=y,DC=corp,DC=local\n"
                "sAMAccountName: y\n")
        entries = rw.parse_ldif(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["servicePrincipalName"],
                         ["HTTP/very.longhost.example"])
        self.assertEqual(entries[0]["msDS-SupportedEncryptionTypes"], ["24"])

    def test_ldif_bad_line(self):
        with self.assertRaises(rw.RoastError):
            rw.parse_ldif("no colon here\n")

    def test_analyze_fixture(self):
        for path in (LDIF, JSON_FIX):
            entries = rw.load_export(path)
            accounts, nd, nt, nk = rw.analyze_entries(entries)
            self.assertEqual(len(accounts), 7, path)
            self.assertEqual(nd, 1, path)
            self.assertEqual(nt, 1, path)
            self.assertEqual(nk, 1, path)
            by_name = {a["name"]: a for a in accounts}
            self.assertTrue(by_name["svc-backup"]["asrep_roastable"])
            self.assertIn("admin", by_name["svc-backup"]["notes"])
            self.assertEqual(by_name["svc-sql"]["spns"],
                             ["MSSQLSvc/sql01.corp.local:1433"])
            self.assertIn("RC4-era keys (no AES advertised)",
                          by_name["svc-web"]["notes"])
            self.assertIn("DES-only enctype", by_name["svc-des"]["notes"])
            self.assertIn("AES keys advertised", by_name["svc-aes"]["notes"])
            self.assertIn("smartcard required (password likely random)",
                          by_name["svc-card"]["notes"])
            self.assertFalse(by_name["jdoe"]["kerberoastable"])
            self.assertFalse(by_name["jdoe"]["asrep_roastable"])
            self.assertIsNotNone(by_name["svc-backup"]["pwd_age_days"])

    def test_filetime(self):
        now = 1800000000
        ft = (now - 3 * 86400 + 11644473600) * 10_000_000
        with mock.patch.object(rw.time, "time", return_value=now):
            self.assertEqual(rw.filetime_to_age_days(str(ft)), 3)
        self.assertIsNone(rw.filetime_to_age_days("0"))
        self.assertIsNone(rw.filetime_to_age_days("9223372036854775807"))
        self.assertIsNone(rw.filetime_to_age_days("abc"))


class EnumCliTest(unittest.TestCase):
    def test_enum_finds_roastables(self):
        r = run_cli(["enum", "--offline", LDIF])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS, r.stderr)
        self.assertIn("svc-backup", r.stdout)
        self.assertIn("svc-sql", r.stdout)
        self.assertIn("AS-REP roastable", r.stdout)
        self.assertNotIn("disabled-svc", r.stdout)
        self.assertNotIn("PC01$", r.stdout)

    def test_enum_json(self):
        r = run_cli(["enum", "--offline", JSON_FIX, "--json"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["mode"], "enum")
        self.assertEqual(data["parsed"], 7)
        self.assertEqual(data["skipped_trust"], 1)
        self.assertEqual(data["skipped_disabled"], 1)
        self.assertEqual(data["asrep_roastable"], ["svc-backup"])
        self.assertEqual(sorted(data["kerberoastable"]),
                         ["svc-aes", "svc-des", "svc-sql", "svc-web"])

    def test_enum_all_and_clean(self):
        r = run_cli(["enum", "--offline", LDIF, "--all"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS)
        self.assertIn("jdoe", r.stdout)
        clean = "dn: CN=nobody,DC=corp,DC=local\nsAMAccountName: nobody\n" \
                "userAccountControl: 512\n"
        with open("/tmp/clean.ldif", "w") as fh:
            fh.write(clean)
        r = run_cli(["enum", "--offline", "/tmp/clean.ldif"])
        self.assertEqual(r.returncode, rw.EXIT_OK, r.stderr)
        self.assertIn("no roastable accounts", r.stdout)

    def test_enum_malformed_no_traceback(self):
        with open("/tmp/bad.ldif", "w") as fh:
            fh.write("this is not: \nreally: ldif\n\x00garbage: \x01\nbad line\n")
        r = run_cli(["enum", "--offline", "/tmp/bad.ldif"])
        self.assertEqual(r.returncode, rw.EXIT_ERROR, r.stdout)
        self.assertTrue(r.stderr.startswith("error:"))
        self.assertNotIn("Traceback", r.stderr)

    def test_enum_missing_file(self):
        r = run_cli(["enum", "--offline", "/tmp/does-not-exist-1234.ldif"])
        self.assertEqual(r.returncode, rw.EXIT_ERROR)
        self.assertTrue(r.stderr.startswith("error: cannot read"))


class LiveKdcTest(unittest.TestCase):
    def setUp(self):
        self.kdc = FakeKDC()
        self.kdc.start()

    def tearDown(self):
        self.kdc.stop()

    def test_asrep_over_tcp(self):
        r = run_cli(["asrep", "--dc", "127.0.0.1", "--port", str(self.kdc.tcp_port),
                     "--realm", "CORP.LOCAL", "--user", "svc-backup"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS, r.stderr)
        h = r.stdout.strip().splitlines()[0]
        self.assertTrue(h.startswith("$krb5asrep$23$svc-backup@CORP.LOCAL:"), h)
        first, rest = h.split(":", 1)[1].split("$", 1)
        self.assertEqual(first, ASREP_CIPHER[:16].hex())
        self.assertEqual(rest, ASREP_CIPHER[16:].hex())
        self.assertIn("hashcat -m 18200", r.stderr)

    def test_asrep_over_udp(self):
        r = run_cli(["asrep", "--dc", "127.0.0.1", "--port", str(self.kdc.udp_port),
                     "--realm", "CORP.LOCAL", "--udp", "--user", "svc-backup"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS, r.stderr)
        self.assertIn("$krb5asrep$23$svc-backup@CORP.LOCAL:", r.stdout)

    def test_asrep_status_lines(self):
        r = run_cli(["asrep", "--dc", "127.0.0.1", "--port", str(self.kdc.tcp_port),
                     "--realm", "CORP.LOCAL",
                     "--user", "svc-backup", "--user", "haspreauth",
                     "--user", "ghost", "--json"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS)
        data = json.loads(r.stdout)
        statuses = {d["user"]: d["status"] for d in data["results"]}
        self.assertEqual(statuses["svc-backup"], "hash")
        self.assertEqual(statuses["haspreauth"], "error")
        self.assertEqual(statuses["ghost"], "error")
        codes = {d["user"]: d.get("error_code") for d in data["results"]}
        self.assertEqual(codes["haspreauth"], 25)
        self.assertEqual(codes["ghost"], 6)

    def test_asrep_unreachable_fails_fast(self):
        r = run_cli(["asrep", "--dc", "127.0.0.1", "--realm", "CORP.LOCAL",
                     "--port", "1", "--user", "svc-backup"])
        self.assertEqual(r.returncode, rw.EXIT_ERROR)
        self.assertTrue(r.stderr.startswith("error: cannot reach 127.0.0.1:1"))
        self.assertNotIn("Traceback", r.stderr)

    def test_roast_full_crypto_path(self):
        r = run_cli(["roast", "--dc", "127.0.0.1", "--port", str(self.kdc.tcp_port),
                     "--realm", "CORP.LOCAL",
                     "--user", "jdoe", "--nthash", NT_HASH_JDOE.hex(),
                     "--spn", "MSSQLSvc/sql01.corp.local:1433"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS, r.stderr)
        h = r.stdout.strip().splitlines()[0]
        self.assertTrue(h.startswith(
            "$krb5tgs$23$*jdoe$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$"), h)
        first, rest = h.split("*$", 1)[1].split("$", 1)
        self.assertEqual(first, TGS_CIPHER_RC4[:16].hex())
        self.assertEqual(rest, TGS_CIPHER_RC4[16:].hex())
        self.assertIn("hashcat -m 13100", r.stderr)
        # the fake KDC validated both our encrypted timestamp and our
        # authenticator; a crypto bug would have come back as error 24
        self.assertIsNone(self.kdc.last_error)

    def test_roast_bad_password(self):
        wrong = "00" * 16
        r = run_cli(["roast", "--dc", "127.0.0.1", "--port", str(self.kdc.tcp_port),
                     "--realm", "CORP.LOCAL",
                     "--user", "jdoe", "--nthash", wrong,
                     "--spn", "MSSQLSvc/sql01.corp.local:1433"])
        self.assertEqual(r.returncode, rw.EXIT_ERROR)
        self.assertIn("error:", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_roast_unknown_spn_still_hashes_rest(self):
        r = run_cli(["roast", "--dc", "127.0.0.1", "--port", str(self.kdc.tcp_port),
                     "--realm", "CORP.LOCAL",
                     "--user", "jdoe", "--nthash", NT_HASH_JDOE.hex(),
                     "--spn", "BADSPN/nope",
                     "--spn", "HTTP/web01.corp.local", "--json"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS)
        data = json.loads(r.stdout)
        st = {d["spn"]: d["status"] for d in data["results"]}
        self.assertEqual(st["BADSPN/nope"], "error")
        self.assertEqual(st["HTTP/web01.corp.local"], "hash")

    def test_roast_aes_fallback(self):
        r = run_cli(["roast", "--dc", "127.0.0.1", "--port", str(self.kdc.tcp_port),
                     "--realm", "CORP.LOCAL",
                     "--user", "jdoe", "--nthash", NT_HASH_JDOE.hex(),
                     "--spn", "AESVC/host.corp.local", "--json"])
        self.assertEqual(r.returncode, rw.EXIT_FINDINGS, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["results"][0]["status"], "hash")
        self.assertTrue(data["results"][0]["hash"].startswith("$krb5tgs$18$"),
                        data["results"][0]["hash"])

    def test_roast_requires_credentials(self):
        r = run_cli(["roast", "--dc", "127.0.0.1", "--realm", "CORP.LOCAL",
                     "--user", "jdoe", "--spn", "x/y"])
        self.assertEqual(r.returncode, rw.EXIT_ERROR)
        self.assertIn("--nthash or --password", r.stderr)

    def test_realm_derivation(self):
        self.assertEqual(rw.resolve_realm("dc01.corp.local", None), "CORP.LOCAL")
        self.assertEqual(rw.resolve_realm("dc01.corp.local", "corp.local"),
                         "CORP.LOCAL")
        with self.assertRaises(rw.RoastError):
            rw.resolve_realm("10.0.0.10", None)


if __name__ == "__main__":
    unittest.main()
