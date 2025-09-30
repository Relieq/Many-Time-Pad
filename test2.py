from typing import List, Optional, Union


def get_ct_byte(ct_number: int, pos: int, c_texts: List[str]) -> Optional[int]:
    """
    Extract a byte from a hexadecimal-encoded ciphertext at a specific position.

    Args:
        ct_number: Index of the ciphertext in the list
        pos: Byte position in the ciphertext (not character position)
        c_texts: List of hex-encoded ciphertext strings

    Returns:
        Integer value of the byte or None if position exceeds ciphertext length
    """
    ct = c_texts[ct_number]
    if pos * 2 >= len(ct):
        return None  # If position exceeds length
    byte_str = ct[pos * 2:pos * 2 + 2]
    return int(byte_str, 16)


def get_key_byte(pos: int, c_texts: List[str]) -> int:
    """
    Attempt to recover a key byte at a specific position by analyzing multiple ciphertexts.
    Uses the assumption that spaces are common in plaintext, and valid plaintext characters
    produce characteristic XOR patterns.

    Args:
        pos: Byte position to analyze
        c_texts: List of hex-encoded ciphertext strings

    Returns:
        Recovered key byte value or 255 if no valid key byte is found
    """
    ct_bytes = []
    for ct_number in range(10):  # First 10 ciphertexts
        b = get_ct_byte(ct_number, pos, c_texts)
        if b is not None:
            ct_bytes.append(b)
        else:
            ct_bytes.append(None)

    num_ct = len(ct_bytes)
    # Create matrix to store XOR values between all ciphertext byte pairs
    ct_xor = [[0] * num_ct for _ in range(num_ct)]
    for i in range(num_ct):
        for j in range(num_ct):
            if i != j and ct_bytes[i] is not None and ct_bytes[j] is not None:
                ct_xor[i][j] = ct_bytes[i] ^ ct_bytes[j]

    # Check each ciphertext byte as potential space character
    for i in range(num_ct):
        if ct_bytes[i] is None:
            continue
        valid = True
        for j in range(num_ct):
            if i == j or ct_bytes[j] is None:
                continue
            xor_val = ct_xor[i][j]
            if xor_val == 0:
                continue
            elif 97 <= xor_val <= 122:  # a-z
                continue
            elif 65 <= xor_val <= 90:  # A-Z
                continue
            else:
                valid = False
                break
        if valid:
            # Assume the plaintext was a space, so derive the key byte
            return ct_bytes[i] ^ ord(' ')

    return 255  # Default if no valid key byte found


def main() -> None:
    """
    Main function to decrypt multiple ciphertexts encrypted with the same key.
    Reads ciphertexts from a file, recovers the key, and decrypts all messages.
    The last ciphertext (11th) is treated as the target message.
    """
    # Read ciphertexts from file
    with open('cyphertexts.txt', 'r') as f:
        c_texts = [line.strip() for line in f if line.strip()]

    if len(c_texts) != 11:
        print("Error: Expected 11 ciphertexts.")
        return

    target = c_texts[10]  # The last ciphertext is our target
    target_len = len(target) // 2  # Each byte is 2 hex characters

    # Decrypt first 10 messages
    msgs = [''] * 10
    key = []  # Store recovered key bytes
    for pos in range(target_len):
        key_byte = get_key_byte(pos, c_texts)
        key.append(key_byte)
        for ct_number in range(10):
            ct_b = get_ct_byte(ct_number, pos, c_texts)
            if ct_b is None:
                continue  # Skip if beyond length
            if key_byte == 255:
                msgs[ct_number] += '_'  # Placeholder for unknown characters
            else:
                msg_char = ct_b ^ key_byte
                msgs[ct_number] += chr(msg_char)

    print("Decrypted messages (first 10):")
    for msg in msgs:
        print(msg)

    # Decrypt the target ciphertext (11th)
    secret = ''
    for pos in range(target_len):
        key_byte = key[pos]
        ct_b = get_ct_byte(10, pos, c_texts)
        if key_byte == 255:
            secret += '_'  # Placeholder for unknown characters
        else:
            msg_char = ct_b ^ key_byte
            secret += chr(msg_char)

    print("\nDecrypted target:")
    print(secret)

    # Save the decrypted target to file
    with open('secret.txt', 'w') as f:
        f.write(secret)


if __name__ == "__main__":
    main()