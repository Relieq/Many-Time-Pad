import secrets


def random(size=16):
    return secrets.token_bytes(size)

def strxor(a, b):
    """XOR two strings together (returns bytes)"""
    # Make sure inputs are bytes objects
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()

    # XOR the bytes together
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(key: str, msg: str):
    c = strxor(key, msg)
    print(c.hex())  # Fixed incomplete print statement
    return c

def main():
    # key = random(1024)
    # print(encrypt(key, "Hello, World!"))
    # Read each cyphertext from file line by line
    with open("cyphertexts.txt", "r") as f:
        cyphertexts = f.readlines()
    # Convert each cyphertext from hex to string
    cyphertexts = [bytes.fromhex(c.strip()) for c in cyphertexts]
    # Find the longest cyphertext
    max_len = max(len(c) for c in cyphertexts)
    # Pad each cyphertext with null bytes to the length of the longest cyphertext
    cyphertexts = [c.ljust(max_len, b'\x00') for c in cyphertexts]
    # XOR each cyphertext with every other cyphertext
    for i in range(len(cyphertexts)):
        for j in range(i + 1, len(cyphertexts)):
            c = strxor(cyphertexts[i], cyphertexts[j])
            print(f"Cyphertext {i} XOR Cyphertext {j}: {c}")

if __name__ == "__main__":
    main()