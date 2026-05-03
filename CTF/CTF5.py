import requests
import time
import re
from binascii import hexlify, unhexlify
from Crypto.Util.Padding import pad

BASE_URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000"
session = requests.Session()

def fetch_ciphertext() -> bytes:
    r = session.get(f"{BASE_URL}/")
    match = re.search(r'[0-9a-fA-F]{32,}', r.text)
    if not match:
        raise RuntimeError("Could not find hex string.")
    hex_blob = match.group(0)
    if len(hex_blob) % 2 != 0: hex_blob = hex_blob[:-1]
    return unhexlify(hex_blob)

def ctf_oracle(iv: bytes, block: bytes) -> bool:
    payload = {"ciphertext_hex": hexlify(iv + block).decode()}  
    
    for attempt in range(3):
        try:
            r = session.post(f"{BASE_URL}/oracle", json=payload, timeout=5)  
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                raise RuntimeError(f"Server network error after 3 attempts: {e}")
            time.sleep(1)
            continue
            
        try:
            data = r.json()
            return data.get("valid_padding", False)
        except requests.exceptions.JSONDecodeError:
            return False

BLOCK_SIZE = 16
DEBUG = True

def decrypt(iv: bytes, ciphertext: bytes, oracle: callable) -> bytes:
    assert len(ciphertext) % BLOCK_SIZE == 0
    
    if iv:
        assert len(iv) == BLOCK_SIZE
    else:
        print("WARNING: The IV was not provided. The attack will proceed without control over the IV.")

    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    result = b''
    xor_value = iv

    for idx, ciphertext_block in enumerate(blocks):
        if xor_value:
            intermediary_value = _get_intermediary_value(ciphertext_block, oracle)
            plaintext = bytes(a ^ b for a, b in zip(xor_value, intermediary_value))
            result += plaintext

        xor_value = ciphertext_block
        if DEBUG:
            print(f'[*] Block completed [{idx+1}/{len(blocks)}]')

    if not iv:
        print("WARNING: Attack was successful but the first block of plaintext was not recovered.")

    return result

def _get_intermediary_value(block: bytes, oracle: callable) -> bytes:
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE+1):
        padding_iv = [0] * (BLOCK_SIZE - pad_val)
        padding_iv += [pad_val ^ b for b in zeroing_iv[-pad_val:]]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)

            if oracle(iv, block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue
                break
        else:
            raise Exception("No valid padding byte found")

        zeroing_iv[-pad_val] = candidate ^ pad_val
        if DEBUG:
            print(f'    [-] Byte completed [{pad_val}/{BLOCK_SIZE}]')

    return zeroing_iv

if __name__ == "__main__":
    print("[*] Fetching ciphertext from server...")
    full_blob = fetch_ciphertext()
    
    # Split 
    iv = full_blob[:BLOCK_SIZE]
    ct = full_blob[BLOCK_SIZE:]
    
    print(f"[*] Starting decryption of {len(ct)} bytes...")
    
    # Run the decrypt function
    plaintext = decrypt(iv, ct, ctf_oracle)
    
    if plaintext:
        # Strip PKCS#7 padding 
        pad_len = plaintext[-1]
        if 1 <= pad_len <= BLOCK_SIZE:
            plaintext = plaintext[:-pad_len]
            
        print(f"\n[+] RECOVERED SECRET: {plaintext.decode(errors='replace')}")
    else:
        print("\n[-] Decryption failed or returned an empty string.")