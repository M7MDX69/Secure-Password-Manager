import json
import os
import secrets

#Step 1: Read domain parameters from config file

def read_parameters(config_file="data/config.json"):
    
    #check if file exists
    
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found.")
    
    #open and read JSON file
    with open(config_file, 'r') as file:
        data = json.load(file)
        
    #extract p and alpha for mathematical operations
    
        p = int(data['p'])
        alpha = int(data['alpha'])
        
    return p,alpha

#Step 2 : private key generation and saving

def generate_private_key(p):
    
    #generate a random number x where 1 < x < p-1
    # secrets is used instead of random for better security
    #random depends on pseudorandom generator which can be predicted 
    #secrets depends on the operating system's randomness that can be more secure and less predicatble
    
    private_key_x = secrets.randbelow(p - 3) + 2
    
    #randbelow(p-1) generates a random number between 0 and p-2
    #randbelow(p-3) generates a random number between 0 and p-4
    #adding 2 to the results shifts the range by 2 resulting in a range of 2 to p-2 as required
    
    return private_key_x


def save_private_key_locally(username , x):
    
    #private key is to be saved locally in a file named after the username
    
    filename = f"keys/{username}_private_key.json"
    
    key_data = {
        "username" : username,
        "private_key" : str(x) 
    }
    
    #write the private key data to the JSON file , indentation added for readability
    with open(filename, 'w') as file:
        json.dump(key_data, file)
        
    print(f" [*] Private key for '{username}' saved successfully")
    
    #Step 3 : public key generation and saving
    
def generate_public_key(p , alpha , x):
        
        #compute public key y = alpha^x mod p
        
        public_key_y = pow(alpha , x , p)
        return public_key_y
    
def save_public_key_locally(username , p , alpha , y):
        
        #save public key locally and then it can be shared with others
        filename = f"keys/{username}_public_key.json"
    
        key_data = {
            "username" : username,
            "p" : str(p),
            "alpha" : str(alpha),
            "public_key" : str(y)
        }
        
        #write the public key data to the JSON file , indentation added for readability
        with open(filename, 'w') as file:
            json.dump(key_data, file)
            
        print(f" [*] Public key for '{username}' saved successfully")
        
        
        #main for testing 
        
if __name__ == "__main__":
    username = input("Enter your username: ")
    private_file = f"{username}_private_key.json"
    public_file = f"{username}_public_key.json"

    # Check if keys already exist to satisfy Property 4 (generated ONCE)
    if os.path.exists(private_file) and os.path.exists(public_file):
        print(f"[*] Keys for {username} already exist. Initialization skipped.")
    else:
        # Run your initialization steps here
        p, alpha = read_parameters()
        x = generate_private_key(p)
        save_private_key_locally(username, x)
        y = generate_public_key(p, alpha, x)
        save_public_key_locally(username, p, alpha, y)