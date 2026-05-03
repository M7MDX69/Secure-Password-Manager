from hashlib import sha256
import json
import random
import math

def generate_k(p):
    k = random.randint(2,p-2)
    while(math.gcd(k,p-1) != 1):
        k = random.randint(2,p-2)
    return k
def extended_euclidean(a, b):
    x_old, x_new = 0 , 1
    y_old, y_new = 1, 0
    q_old, q_new = 0, 0
    r_old , r_new = a , b

    while(r_new != 0):
        q_old, q_new = q_new , r_old // r_new
        r_old, r_new = r_new, r_old - q_new * r_new
        x_old , x_new = x_new , x_old - q_new * x_new
        y_old , y_new = y_new, y_old - q_new * y_new
    return y_old % b
    
def sign_vault(vault_data: dict, private_key: dict) -> dict:
    """Sign vault_data with ElGamal; returns a new dict with 'signature' added."""
    p     = int(private_key['p'])
    alpha = int(private_key['alpha'])
    x     = int(private_key['private_key'])

    content     = {k: v for k, v in vault_data.items() if k != 'signature'}
    content_str = json.dumps(content, sort_keys=True)
    M           = int(sha256(content_str.encode('utf-8')).hexdigest(), 16)

    k     = generate_k(p)
    k_inv = extended_euclidean(k, p - 1)
    S1    = pow(alpha, k, p)
    S2    = ((M - x * S1) * k_inv) % (p - 1)

    signed              = dict(vault_data)
    signed['signature'] = {'S1': str(S1), 'S2': str(S2)}
    return signed


def verify_vault(vault_data: dict, public_key: dict) -> bool:
    """Verify the ElGamal signature on vault_data. Returns True if valid, False otherwise."""
    if 'signature' not in vault_data:
        return False

    p     = int(public_key['p'])
    alpha = int(public_key['alpha'])
    y     = int(public_key['public_key'])
    S1    = int(vault_data['signature']['S1'])
    S2    = int(vault_data['signature']['S2'])

    content     = {k: v for k, v in vault_data.items() if k != 'signature'}
    content_str = json.dumps(content, sort_keys=True)
    M           = int(sha256(content_str.encode('utf-8')).hexdigest(), 16)

    left_side  = pow(alpha, M, p)
    right_side = (pow(y, S1, p) * pow(S1, S2, p)) % p
    return left_side == right_side

if __name__ == "__main__":
    current_user = input("Enter Your Username: ")
    vault_path  = f"vaults/{current_user}_vault.json"
    pr_key_path = f"keys/{current_user}_private_key.json"
    pu_key_path = f"keys/{current_user}_public_key.json"

    vault_data  = json.load(open(vault_path))
    private_key = json.load(open(pr_key_path))
    public_key  = json.load(open(pu_key_path))

    signed = sign_vault(vault_data, private_key)
    json.dump(signed, open(vault_path, 'w'), indent=4)

    if verify_vault(signed, public_key):
        print(f"[*] SUCCESS: Vault for '{current_user}' signed and verified.")
    else:
        print("[!] ERROR: Signature verification failed.")
