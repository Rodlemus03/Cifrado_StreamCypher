import base64

def _key_to_seed(key):
    if isinstance(key, int):
        return key & 0xffffffff
    s = str(key)
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xffffffff
    return h

def keystream(key, n):
    state = _key_to_seed(key)
    out = bytearray()
    for _ in range(n):
        state = (1664525 * state + 1013904223) & 0xffffffff
        out.append((state >> 24) & 0xff)
    return bytes(out)

def encrypt_xor(plaintext, key):
    if isinstance(plaintext, str):
        pt = plaintext.encode("utf-8")
    else:
        pt = bytes(plaintext)
    ks = keystream(key, len(pt))
    ct = bytearray()
    for i in range(len(pt)):
        ct.append(pt[i] ^ ks[i])
    return bytes(ct)

def decrypt_xor(ciphertext, key, as_text=True, encoding="utf-8", errors="strict"):
    if isinstance(ciphertext, str):
        ct = ciphertext.encode(encoding, errors=errors)
    else:
        ct = bytes(ciphertext)
    ks = keystream(key, len(ct))
    pt = bytearray()
    for i in range(len(ct)):
        pt.append(ct[i] ^ ks[i])
    pt_bytes = bytes(pt)
    if as_text:
        return pt_bytes.decode(encoding, errors=errors)
    return pt_bytes

def to_hex(b):
    h = []
    for x in b:
        hx = hex(x)[2:]
        if len(hx) == 1:
            hx = "0" + hx
        h.append(hx)
    return "".join(h)

def from_hex(hex_str):
    s = str(hex_str).strip().lower()
    if len(s) % 2 != 0:
        s = "0" + s
    out = bytearray()
    for i in range(0, len(s), 2):
        out.append(int(s[i:i+2], 16))
    return bytes(out)

def to_b64(b):
    return base64.b64encode(bytes(b)).decode("ascii")

def from_b64(s):
    return base64.b64decode(str(s).encode("ascii"))

def xor_bytes(a, b):
    a = bytes(a)
    b = bytes(b)
    n = min(len(a), len(b))
    out = bytearray()
    for i in range(n):
        out.append(a[i] ^ b[i])
    return bytes(out)

def reused_keystream_attack(ciphertext1, ciphertext2):
    return xor_bytes(ciphertext1, ciphertext2)
def separador():
    print("-" * 40)
if __name__ == "__main__":
    msg = "hola mundo"
    key = "Holis123"
    c = encrypt_xor(msg, key)
    print("cipher(hex):", to_hex(c))
    print("cipher(b64):", to_b64(c))
    print("desencriptado:", decrypt_xor(c, key, as_text=True))
    separador()
    msg2 = "Hola hola soy el cejas"
    key2 = "cifrado2026"
    c2 = encrypt_xor(msg2, key2)
    print("cipher2(hex):", to_hex(c2))
    print("cipher2(b64):", to_b64(c2))
    print("desencriptado 2:", decrypt_xor(c2, key2, as_text=True))
    separador()
    msg3 = "1234567890!@#$%^&*()_+-="
    key3 = 987654321
    c3 = encrypt_xor(msg3, key3)
    print("cipher3(hex):", to_hex(c3))
    print("cipher3(b64):", to_b64(c3))
    print("desencriptado 3:", decrypt_xor(c3, key3, as_text=True))
    separador()
    m = "Lo mismo con diferentes claves"
    ca = encrypt_xor(m, "claveA")
    cb = encrypt_xor(m, "claveB")
    print("variacion_clave_hex_A:", to_hex(ca))
    print("variacion_clave_hex_B:", to_hex(cb))
    separador()
    keyr = "reutilizada 123"
    p1 = "ataque al amanecer"
    p2 = "retirada al anochecer"
    c1 = encrypt_xor(p1, keyr)
    c2 = encrypt_xor(p2, keyr)
    print("c1(hex):", to_hex(c1))
    print("c2(hex):", to_hex(c2))
    print("c1_xor_c2(hex):", to_hex(reused_keystream_attack(c1, c2)))
