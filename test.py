import unittest
import base64

import strem_cypher as xc


class TestKeyToSeed(unittest.TestCase):
    def test_int_key_masks_32bit(self):
        self.assertEqual(xc._key_to_seed(0), 0)
        self.assertEqual(xc._key_to_seed(0xffffffff), 0xffffffff)
        self.assertEqual(xc._key_to_seed(0x1ffffffff), 0xffffffff)

    def test_str_key_is_deterministic(self):
        a = xc._key_to_seed("Holis123")
        b = xc._key_to_seed("Holis123")
        c = xc._key_to_seed("Holis124")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_non_str_key_is_converted(self):
        self.assertEqual(xc._key_to_seed(12345), xc._key_to_seed(12345))
        self.assertEqual(xc._key_to_seed(12.5), xc._key_to_seed("12.5"))


class TestKeystream(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(xc.keystream("k", 0)), 0)
        self.assertEqual(len(xc.keystream("k", 1)), 1)
        self.assertEqual(len(xc.keystream("k", 32)), 32)

    def test_deterministic_same_key(self):
        self.assertEqual(xc.keystream("abc", 64), xc.keystream("abc", 64))

    def test_different_keys_different_stream(self):
        self.assertNotEqual(xc.keystream("abc", 32), xc.keystream("abd", 32))

    def test_int_and_str_key_work(self):
        self.assertEqual(len(xc.keystream(123, 10)), 10)
        self.assertEqual(len(xc.keystream("123", 10)), 10)


class TestEncryptDecrypt(unittest.TestCase):
    def test_roundtrip_text(self):
        msg = "hola mundo"
        key = "Holis123"
        c = xc.encrypt_xor(msg, key)
        self.assertIsInstance(c, (bytes, bytearray))
        p = xc.decrypt_xor(c, key, as_text=True)
        self.assertEqual(p, msg)

    def test_roundtrip_bytes(self):
        msg = b"\x00\x01\x02\xfe\xffhola"
        key = "k"
        c = xc.encrypt_xor(msg, key)
        p = xc.decrypt_xor(c, key, as_text=False)
        self.assertEqual(p, msg)

    def test_encrypt_accepts_bytes_like(self):
        msg = bytearray(b"abc123")
        c = xc.encrypt_xor(msg, "k")
        self.assertEqual(xc.decrypt_xor(c, "k", as_text=False), b"abc123")

    def test_wrong_key_not_equal_plaintext(self):
        msg = "mensaje secreto"
        c = xc.encrypt_xor(msg, "claveA")
        p_wrong = xc.decrypt_xor(c, "claveB", as_text=True, errors="ignore")
        self.assertNotEqual(p_wrong, msg)

    def test_decrypt_str_ciphertext_path(self):
        msg = "hola"
        key = "k"
        c = xc.encrypt_xor(msg, key)
        hex_ct = xc.to_hex(c)
        ct_bytes = xc.from_hex(hex_ct)
        self.assertEqual(xc.decrypt_xor(ct_bytes, key, as_text=True), msg)

    def test_decrypt_as_text_strict_can_fail(self):
        msg = "hola mundo"
        key = "k1"
        c = xc.encrypt_xor(msg, key)
        with self.assertRaises(UnicodeDecodeError):
            xc.decrypt_xor(c, "otra_clave", as_text=True, errors="strict")


class TestHexBase64(unittest.TestCase):
    def test_hex_roundtrip(self):
        b = b"\x00\x01\x02\x10\xff"
        h = xc.to_hex(b)
        self.assertEqual(xc.from_hex(h), b)

    def test_hex_odd_length_is_padded(self):
        self.assertEqual(xc.from_hex("f"), b"\x0f")
        self.assertEqual(xc.from_hex("0f"), b"\x0f")

    def test_hex_accepts_uppercase_and_spaces(self):
        self.assertEqual(xc.from_hex(" 0A0B "), b"\x0a\x0b")

    def test_b64_roundtrip(self):
        b = b"hola\x00\xff"
        s = xc.to_b64(b)
        self.assertEqual(xc.from_b64(s), b)

    def test_b64_matches_stdlib(self):
        b = b"test"
        self.assertEqual(xc.to_b64(b), base64.b64encode(b).decode("ascii"))
        self.assertEqual(xc.from_b64(xc.to_b64(b)), b)


class TestXorHelpers(unittest.TestCase):
    def test_xor_bytes_length_is_min(self):
        a = b"\x01\x02\x03"
        b = b"\x10\x20"
        out = xc.xor_bytes(a, b)
        self.assertEqual(len(out), 2)

    def test_xor_bytes_basic(self):
        self.assertEqual(xc.xor_bytes(b"\x00", b"\xff"), b"\xff")
        self.assertEqual(xc.xor_bytes(b"\xaa", b"\xaa"), b"\x00")

    def test_xor_bytes_commutative_for_overlap(self):
        a = b"\x01\x02\x03\x04"
        b = b"\x10\x20"
        self.assertEqual(xc.xor_bytes(a, b), xc.xor_bytes(b, a))

    def test_reused_keystream_attack_is_xor(self):
        c1 = b"\x01\x02\x03"
        c2 = b"\x10\x20\x30"
        self.assertEqual(xc.reused_keystream_attack(c1, c2), xc.xor_bytes(c1, c2))

    def test_reused_keystream_attack_property(self):
        key = "reutilizada 123"
        p1 = b"ataque al amanecer"
        p2 = b"retirada al anochecer"
        c1 = xc.encrypt_xor(p1, key)
        c2 = xc.encrypt_xor(p2, key)
        x = xc.reused_keystream_attack(c1, c2)
        self.assertEqual(x, xc.xor_bytes(p1, p2))


if __name__ == "__main__":
    unittest.main()
