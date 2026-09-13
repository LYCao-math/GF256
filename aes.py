# 1. Basic arithmetic in K = GF(2^8) = F2[x]/(p(x))（对应standard irreducible polynomial in the Euclidean domain F2[x] p(x) = x^8+x^4+x^3+x+1）
def poly_degree(a: int) -> int:
    """F2[x]/(p(x))上多项式(polynomial)的最高次幂，a=0返回-1(代数中规定0多项式次数应为-∞),
    将整数转化为二进制形式以对应域K中一个多项式"""
    return a.bit_length() - 1 if a != 0 else -1

def F2_mult(a: int, b: int) -> int:
    """Polynomial multiplication over F2 (addition is XOR),每个整数对应的多项式相乘后没有模p(x).实质上是b的每一位乘以a,然后异或赋值
    如 15*12 = 68: (x^3+x^2+x+1) * (x^3+x^2) = (x^6+x^2) = 68
    1111 * 1100 = 111100 + 1111000 = 1000100"""
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        b >>= 1
    return res

def F2_divi(a: int, b: int) -> tuple[int, int]:
    """Euclid整环 F2[x]多项式带余除法，返回(商q, 余数r)"""
    if b == 0:
        raise ZeroDivisionError("除数不为0多项式")
    deg_a, deg_b = poly_degree(a), poly_degree(b)
    q, r = 0, a
    while deg_a >= deg_b:
        diff = deg_a - deg_b
        q ^= 1 << diff
        r ^= b << diff
        deg_a = poly_degree(r)
    return q, r

def GF256_mult(a: int, b: int, ir_poly: int = 0x11b) -> int:
    """Multiplication in GF(2^8), reduced modulo the irreducible polynomial p(x)"""
    origin = F2_mult(a, b)
    _, rem = F2_divi(origin, ir_poly)
    return rem

def GF256_inve(a: int, ir_poly: int = 0x11b) -> int:
    """Multiplicative inverse in GF(2^8), using the extended Euclidean algorithm"""
    if a == 0:
        raise ZeroDivisionError("0无乘法逆元")
    old_r, r = a, ir_poly
    old_s, s = 1, 0
    while r != 0:
        q, rem = F2_divi(old_r, r)
        old_r, r = r, rem
        old_s, s = s, old_s ^ F2_mult(q, s)
    trash, inv = F2_divi(old_s, ir_poly)
    return inv

# 2. Generate the standard AES S-box
def generate_sbox() -> list[int]:
    """生成AES正向S盒,used for byte substitution and inverse lookup during decryption.步骤:
    在GF(2⁸)内求逆元,然后线性变换"""
    sbox = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else GF256_inve(i)
        # 线性变换：b_i = s_i ^ s_{i+4} ^ s_{i+5} ^ s_{i+6} ^ s_{i+7} ^ c_i (c=0x63)
        res = 0
        for bit in range(8):
            b = (inv >> bit) & 1
            b4 = (inv >> ((bit + 4) % 8)) & 1
            b5 = (inv >> ((bit + 5) % 8)) & 1
            b6 = (inv >> ((bit + 6) % 8)) & 1
            b7 = (inv >> ((bit + 7) % 8)) & 1
            c = (0x63 >> bit) & 1
            res |= ((b ^ b4 ^ b5 ^ b6 ^ b7 ^ c) << bit)
        sbox[i] = res
    return sbox

SBOX = generate_sbox()

#  3. Key expansion: generate 11 round keys
def rot_word(word: list[int]) -> list[int]:
    """Rotate a 4-byte word left by one byte：[b0,b1,b2,b3] → [b1,b2,b3,b0]"""
    return word[1:] + word[:1]

def sub_word(word: list[int]) -> list[int]:
    """Apply the S-box independently to each byte"""
    return [SBOX[b] for b in word]

def key_expansion(main_key: bytes) -> list[list[list[int]]]:
    """Key expansion: input a 16-byte key and output 11 round-key state matrices"""
    if len(main_key) != 16:
        raise ValueError("主密钥必须为16字节")

    """Round constants obtained from powers of x in the field K"""
    Rcon = [[0x01, 0, 0, 0], [0x02, 0, 0, 0], [0x04, 0, 0, 0], [0x08, 0, 0, 0], [0x10, 0, 0, 0],
            [0x20, 0, 0, 0], [0x40, 0, 0, 0], [0x80, 0, 0, 0], [0x1b, 0, 0, 0], [0x36, 0, 0, 0]]

    # Initialize: split the 16-byte key into four 4-byte words,从0开始拆分，主密钥长度保证了分隔有效
    w = []
    for i in range(4):
        w.append(list(main_key[i * 4: (i + 1) * 4]))

    # Generate 44 words (11 round keys × 4 words)（共11轮 × 4字/轮）,w[0],w[1],w[2],w[3]为上述主密钥,然后通过下述通项进行递归得到
    for i in range(4, 44):
        temp = w[i - 1].copy()
        if i % 4 == 0:
            # 移位,查S盒
            temp = sub_word(rot_word(temp))
            # 异或对应轮常数,每一行4个都要异或,分两步进行.
            temp = [temp[j] ^ Rcon[i // 4 - 1][j] for j in range(4)]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    # Convert the words into 11 4×4 round-key matrices using column-major order
    round_keys = []
    for r in range(11):
        state = [[0] * 4 for t in range(4)]
        for col in range(4):
            word = w[r * 4 + col]
            for row in range(4):
                state[row][col] = word[row]
        round_keys.append(state)
    return round_keys

# 4. Round transformation functions
def bytes_to_state(block: bytes) -> list[list[int]]:
    """Convert a 16-byte block to a 4×4 state matrix (column-major order)"""
    state = [[0] * 4 for t in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col *4 + row]
    return state

def state_to_bytes(state: list[list[int]]) -> bytes:
    """Convert a 4×4 state matrix to a 16-byte block (column-major order)"""
    res = []
    for col in range(4):
        for row in range(4):
            res.append(state[row][col])
    return bytes(res)

def sub_bytes(state: list[list[int]]) -> None:
    """SubBytes: substitute every byte using the S-box"""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]

def shift_rows(state: list[list[int]]) -> None:
    """ShiftRows: row 0 unchanged; rows 1, 2, and 3 shifted left by 1, 2, and 3 bytes"""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def mix_columns(state: list[list[int]]) -> None:
    """MixColumns: multiply each column by the AES matrix over GF(2^8)"""
    # 加密列混合矩阵 M = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    for col in range(4):
        s0, s1, s2, s3 = state[0][col], state[1][col], state[2][col], state[3][col]
        state[0][col] = GF256_mult(2, s0) ^ GF256_mult(3, s1) ^ s2 ^ s3
        state[1][col] = s0 ^ GF256_mult(2, s1) ^ GF256_mult(3, s2) ^ s3
        state[2][col] = s0 ^ s1 ^ GF256_mult(2, s2) ^ GF256_mult(3, s3)
        state[3][col] = GF256_mult(3, s0) ^ s1 ^ s2 ^ GF256_mult(2, s3)

def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    """AddRoundKey: XOR the state with the round key byte by byte"""
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]

#  5. PKCS#7 padding
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding：补齐到整数个分组，填充字节值=填充长度"""
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

# 6. Remove PKCS#7 padding
def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = data[-1]
    if data[-1]<1 or data[-1]>16:
        raise ValueError('未填充或数据损坏')
    return data[:-pad_len]

#  7. AES encryption
def AES_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128 in ECB mode
    param plaintext: plaintext (arbitrary-length bytes)
    param key: 16-byte key
    return: ciphertext bytes
    """
    round_keys = key_expansion(key)
    padded_data = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    # Encrypt block by block; each block contains 16 bytes
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i + 16]
        state = bytes_to_state(block)

        # Initial AddRoundKey
        add_round_key(state, round_keys[0])

        # Rounds 1–9: SubBytes, ShiftRows, MixColumns, AddRoundKey
        for r in range(1,10):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, round_keys[r])

        # Round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, round_keys[10])
        ciphertext.extend(state_to_bytes(state))
    return ciphertext

#  Example using the key 00, 01, ..., 0f
key = bytes(range(16))
plaintext = b"mathematical science"
cipher = AES_encrypt(plaintext, key)
print("Ciphertext (hex):", cipher.hex())

# 8. Decryption; ciphertext in hexadecimal must first be converted to bytes
def AES_decrypt(ciphertext: bytes, key:bytes) -> bytes:
    round_keys = key_expansion(key)
    result_words = bytearray()
    for i in range(0, len(ciphertext), 16):
        decy_1 = []
        # Undo the final encryption round
        block = ciphertext[i:i + 16]
        state = bytes_to_state(block)
        add_round_key(state, round_keys[10])
        # Apply the inverse row shift
        for j in range(3):
            shift_rows(state)
        # Inverse S-box lookup
        for s in range(4):
            piece = []
            for t in range(4):
                piece.append(SBOX.index(state[s][t]))
            decy_1.append(piece)
        # Decrypt rounds 9–1
        for times in range(9,0,-1):
            # AddRoundKey; addition in GF(256) is XOR
            add_round_key(decy_1, round_keys[times])
            # Multiply by the inverse of the MixColumns matrix over GF(256).
            # M^-1 = [[0x0e,0x0b,0x0d,0x09],[0x09,0x0e,0x0b,0x0d],
            #        [0x0d,0x09,0x0e,0x0b],[0x0b,0x0d,0x09,0x0e]]
            for col in range(4):
                s0, s1, s2, s3 = decy_1[0][col], decy_1[1][col], decy_1[2][col], decy_1[3][col]
                decy_1[0][col] = (GF256_mult(0x0e, s0) ^ GF256_mult(0x0b, s1)
                                ^ GF256_mult(0x0d, s2) ^ GF256_mult(0x09, s3))
                decy_1[1][col] = (GF256_mult(0x09, s0) ^ GF256_mult(0x0e, s1)
                                ^ GF256_mult(0x0b, s2) ^ GF256_mult(0x0d, s3))
                decy_1[2][col] = (GF256_mult(0x0d, s0) ^ GF256_mult(0x09, s1)
                                ^ GF256_mult(0x0e, s2) ^ GF256_mult(0x0b, s3))
                decy_1[3][col] = ((GF256_mult(0x0b, s0)) ^GF256_mult(0x0d, s1)
                                ^ GF256_mult(0x09, s2) ^ GF256_mult(0x0e, s3))
            # Apply the inverse row shift
            for j in range(3):
                shift_rows(decy_1)
            # Inverse S-box lookup
            decy_2 = decy_1.copy()
            decy_1 = []
            for s in range(4):
                piece = []
                for t in range(4):
                    piece.append(SBOX.index(decy_2[s][t]))
                decy_1.append(piece)
        # Final AddRoundKey with the initial key
        add_round_key(decy_1, round_keys[0])
        result_words.extend(state_to_bytes(decy_1))
    return result_words
# Example: decrypt the ciphertext obtained above'mathematical science'the hexadecimal ciphertext
results = AES_decrypt(bytes.fromhex('dabe0b1912d04d8109635581f40a15a3f1552a7c293adbfed819451f79f37f91'), key)
print(bytes(pkcs7_unpad(results)))




