from elgamal import generate_private_key
from elgamal import generate_public_key
from hashlib import sha256
import json
import random
import math
import sys

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
    
def sign_vault(username, encrypted_vault, p, alpha , x):
#     Signing process:
# a. Compute a SHA-256 hash of the vault contents (encrypted content).
# b. Sign the hash using the user's private key (ElGamal signature)
# c. Store the signature alongside the vault.
    SHA= sha256(encrypted_vault.encode('utf-8')).hexdigest()
    M = int(SHA, 16)
    
    #we need a random integer k <q-1 and gcd(k, p-1) is 1
    k = generate_k(p)
    k_inv = extended_euclidean(k , p-1)


    S1= pow(alpha, k, p)   # alpha power k mod q
    S2 = ((M - x * S1) * k_inv) % (p - 1)

    vault = f"vaults/{username}_vault.json"
    with open(vault , 'r') as file:
        vault_data = json.load(file)

    vault_data['signature'] = {'S1': str(S1), 'S2': str(S2)}

    with open(vault, 'w') as file:
        json.dump(vault_data, file, indent=4)

    print(f"[*] Success: Vault for '{username}' has been signed.")


def verify_vault(username, encrypted_vault, p, alpha, y):
    vault = f"vaults/{username}_vault.json"
    SHA = sha256(encrypted_vault.encode('utf-8')).hexdigest()
    M = int(SHA, 16)
    with open(vault, 'r') as file:
        vault_data = json.load(file)
    if 'signature' not in vault_data:
        print("[!] ERROR: No signature found. Vault is completely unverified!")
        sys.exit()
    S1 = int(vault_data['signature']['S1'])
    S2 = int(vault_data['signature']['S2'])
    
    left_side = pow(alpha, M, p)
    right_side = (pow(y, S1, p) * pow(S1, S2, p)) % p
    if left_side == right_side:
        print(f"[*] SUCCESS: Vault integrity verified for '{username}'. It is safe to decrypt.")
        return True
    else:
        print("\n SECURITY WARNING ")
        print("The vault digital signature is invalid.")
        sys.exit()
    




# a. Compute the SHA-256 hash of the current vault contents (encrypted content)
# b. Verify the stored signature against the hash using the user's ElGamal public key.
# c. If verification fails, refuse to open and warn the user.
    pass

if __name__ == "__main__":
    current_user = input("Enter Your Username: ")
    private_key = f"keys/{current_user}_private_key.json"
    public_key = f"keys/{current_user}_public_key.json"
    vault = f"vaults/{current_user}_vault.json"
    data = json.loads(open(vault).read())
    pu_key = json.loads(open(public_key).read())
    pr_key = json.loads(open(private_key).read())
    data = json.loads(open(vault).read())
    #print(data)
    encrypted_vault = data['encrypted_vault']
    p = int(pu_key['p'])
    alpha = int(pu_key['alpha'])
    y = int(pu_key['public_key'])
    x = int(pr_key['private_key'])
    sign_vault(current_user, encrypted_vault, p, alpha, x)
    verify_vault(current_user, encrypted_vault, p, alpha, y)
