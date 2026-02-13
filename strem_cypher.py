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

def to_hex(b):
    h = []
    for x in b:
        hx = hex(x)[2:]
        if len(hx) == 1:
            hx = "0" + hx
        h.append(hx)
    return "".join(h)

if __name__ == "__main__":
    msg = "hola mundo"
    key = "clave123"
    c = encrypt_xor(msg, key)
    print("cipher(hex):", to_hex(c))
