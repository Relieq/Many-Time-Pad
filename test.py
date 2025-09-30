def bxor(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays of the same length."""
    return bytes(x ^ y for x, y in zip(a, b))

def is_letter(b):
    return (ord('A')<=b<=ord('Z')) or (ord('a')<=b<=ord('z'))

def top_positions(votes, threshold=7):
    return [i for i, v in enumerate(votes) if v >= threshold]

# decrypt known positions
def is_printable(b):
    return 32 <= b <= 126

def reveal(Ci, key):
    out=[]
    for pos, b in enumerate(Ci[:len(key)]):
        if key[pos] is None:
            out.append('_')
        else:
            ch = b ^ key[pos]
            out.append(chr(ch) if is_printable(ch) else '·')
    return ''.join(out)

def score_key_segment(C_list, j, key_seg):
    """Trả về số ký tự in được khi áp đoạn khóa key_seg vào tất cả C tại offset j."""
    total = 0
    for Ci in C_list:
        for k, kk in enumerate(key_seg):
            ch = Ci[j+k] ^ kk
            if 32 <= ch <= 126:
                total += 1
    return total

def try_crib_positions(C_list, C_target, crib: bytes):
    best = []
    L = len(C_target) - len(crib) + 1
    for j in range(L):
        # suy khóa tạm tại vị trí j
        key_seg = bytes(C_target[j+k] ^ crib[k] for k in range(len(crib)))
        s = score_key_segment(C_list, j, key_seg)
        best.append((s, j, key_seg))
    # trả về top vài vị trí điểm cao nhất
    best.sort(reverse=True)  # sort theo score
    return best[:5]

def apply_segment_to_key(key, j, key_seg):
    for k, kk in enumerate(key_seg):
        key[j+k] = kk


C_hex = [line.strip() for line in open("cyphertexts.txt")]
C = [bytes.fromhex(cyphertext.strip()) for cyphertext in C_hex]
min_len = min(len(c) for c in C)

C_target = C[-1]
# ascii_str = ' '.join(chr(x) if 32 <= x <= 126 else '.' for x in C_target)
# print(ascii_str)

for i, cyphertext in enumerate(C):
    print(f"Cyphertext {i}: {cyphertext}")

print()

# XOR each cyphertext with the C_target (the last one)
xored = []
for i in range(10):
    xored.append(bxor(C[i], C_target))
    print(f"Cyphertext {i} XOR target: {xored[i]}")

# voting spaces for C_target
votes = [0] * min_len
for i in range(10):
    for pos, b in enumerate(xored[i]):
        if is_letter(b):
            votes[pos]+=1
print(votes)

# pick positions with high votes, derive key there
key = [None] * min_len
for pos in top_positions(votes):
    key[pos] = C_target[pos] ^ 0x20  # assume target has ' '

print(key)
print(f'Target:\n{reveal(C_target, key)}')

crib = b"The"
candidates = try_crib_positions(C, C_target, crib)
print("Top candidates (score, offset):", [(s, j) for s, j, _ in candidates])

# lấy ứng viên tốt nhất, cập nhật khóa và xem target bung thêm chưa
s, j, key_seg = candidates[0]
apply_segment_to_key(key, j, key_seg)
print("Score best:", s, "at offset", j)
print(f"Target now:\n{reveal(C_target, key)}")

