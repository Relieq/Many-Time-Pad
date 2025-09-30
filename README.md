# Programming Assignment 1
## Many Time Pad 

Let us see what goes wrong when a one-time pad (or stream cipher) key  is used more than once.  Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with one time pad, all with the same one-time pad key.  Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution. 

Hint: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z].

### ciphertext #1:
```
315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e
```
### ciphertext #2:
```
234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f
```
### ciphertext #3:
```
32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb
```
### ciphertext #4:
```
32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa
```
### ciphertext #5:
```
3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070
```
### ciphertext #6:
```
32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4
```
### ciphertext #7:
```
32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce
```
### ciphertext #8:
```
315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3
```
### ciphertext #9:
```
271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027
```
### ciphertext #10:
```
466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83
```
### target ciphertext (decrypt this one): 
```
32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904
```
## Python code
For completeness, here is the python script used to generate the ciphertexts.

(it doesn't matter if you can't read this)

```python
def random(size=16):
    return open("/dev/urandom").read(size)

def encrypt(key, msg):
    c = strxor(key, msg)
    print
    print c.encode('hex')
    return c

def main():
    key = random(1024)
    ciphertexts = [encrypt(key, msg) for msg in MSGS]
```

## Requirements

### Deliverables
1. secret.txt: the recovered plaintext of the last ciphertext.
2. solve.py (or c, cpp, exel,...): your working code.
3. README.md: short explanation (≤ 300 words) of your approach.

### Grading (100 pts)
-  Correct secret message (70 pts).
-  Clear, runnable code (20 pts).
-  Concise README (10 pts).

For more details about the assignment, refer to the following link:
[Assignment Description](https://www.dropbox.com/scl/fo/50zruygolfcicpd6z856p/h?rlkey=3t5xjy0xm3lqkgh3fpqwbc77r&dl=0)

# My solution
## Approach
The key point is that the same key is used to encrypt multiple plaintexts.
Let x_i be the i-th character of a plaintext, y_i be the i-th character of the corresponding ciphertext, and k_i be the i-th character of the key. 
Then we have:
```
y_i = x_i XOR k_i
```
If we have two ciphertexts y_i and y_j encrypted with the same key, we can XOR them together:
```
y_i XOR y_j = (x_i XOR k_i) XOR (x_j XOR k_j) = x_i XOR x_j
```
This means that by XORing two ciphertexts, we eliminate the key and get the XOR of the two plaintext characters.
This is useful because we can exploit the properties of the XOR operation and the characteristics of English text to make 
educated guesses about the plaintext characters.
### Strategy
By assumption, the character at that position in the chosen plaintext might be either a letter or a space.

XOR Behavior Analysis
* When position contains a space:
  * XOR with another letter → produces that letter
  * XOR with another space → produces null (0)
* When position contains a letter:
  * XOR with the same case letter → produces random control characters
  * XOR with a different case letter → produces numbers or punctuation
  * XOR with space → produces the same letter with a case flipped

This pattern allows for systematic decryption by analyzing character frequencies in XORed ciphertext pairs.

**NOTE:** My answer is **The secret message is: When using a stream cipher, never use the key more than once**

## Implementation (You can read this section right into solve.py)
* First, I create a file cyphertexts.txt and copy the 11 ciphertexts into it to read them in the code more easily.
* The code below in solve.py implements the way I described above to recover the key and decrypt the messages. 
I have also explained each code snippet in its own comments.
```python
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
        Recovered key byte value (DEC) or 255 if no valid key byte is found
    """
    ct_bytes = []
    for ct_number in range(10):  # First 10 ciphertexts
        b = get_ct_byte(ct_number, pos, c_texts)
        if b is not None:
            ct_bytes.append(b)
        else:
            ct_bytes.append(None)

    # Create matrix to store XOR values between all ciphertext byte pairs
    ct_xor = [[0] * 10 for _ in range(10)]
    for i in range(10):
        for j in range(10):
            if i != j and ct_bytes[i] is not None and ct_bytes[j] is not None:
                ct_xor[i][j] = ct_bytes[i] ^ ct_bytes[j]

    # Check each ciphertext byte as a potential space character
    possible_keys = set()
    for i in range(10):
        if ct_bytes[i] is None:
            continue
        valid = True
        for j in range(10):
            if i == j or ct_bytes[j] is None:
                continue
            xor_val = ct_xor[i][j]
            if xor_val == 0:  # Same character, maybe space or not
                continue
            elif 97 <= xor_val <= 122:  # a-z
                continue
            elif 65 <= xor_val <= 90:  # A-Z
                continue
            else:  # Control chars, punctuation, numbers
                valid = False
                break
        if valid:
            # Assume the plaintext was a space, so derive the key byte: k = y_i ^ x_i or k = y_j ^ x_j
            possible_keys.add(ct_bytes[i] ^ ord(' '))

    if len(possible_keys) == 1:
        return list(possible_keys)[0]
    elif len(possible_keys) > 1:
        # Conflict: Use score to choose best
        best_key, best_score = 255, -1
        for k in possible_keys:
            score = 0
            for b in ct_bytes:
                if b is not None:
                    d = b ^ k
                    if 32 <= d <= 126:  # Printable
                        score += 1
            if score > best_score:
                best_score = score
                best_key = k
        return best_key

    return 255  # Default if no valid key byte found


def main() -> None:
    """
    Main function to decrypt multiple ciphertexts encrypted with the same key.
    Reads ciphertexts from a file, recovers the key, and decrypts all messages.
    The last ciphertext (11th) is treated as the target message.
    """
    # Read ciphertexts from a file
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
```
* Run the solve.py script to generate the secret.txt file containing the decrypted message (partially decrypted with placeholders for unknown characters).
```
Th_ secuet_mes_age_is: Wh__ us_______tr____cipher,_nev_r_use the key more than on__
```
* So I manually fixed some obvious mistakes and filled in the missing characters based on context to get the final secret:
```
The secret message is: When using a stream cipher, never use the key more than once
```
