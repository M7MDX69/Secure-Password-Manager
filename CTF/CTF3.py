def ctf3(filename):
    
    print(f"[*] Reading file: {filename}")
    
    try:
        with open(filename, 'r') as f:
            data = f.read().split()
            
    except FileNotFoundError:
        print(f"[!] File not found.")
        return
    
    flag = ""
    
    for number_str in data:
        
        #convert text string into actual integer
        shifted_value = int(number_str)
        
        #reverse left shift by right shifting
        
        original_value = shifted_value >> 1
        
        #convert the ascii decimal back to text
        
        character = chr(original_value)
        
        flag += character
        
    print(f"\n[+] Decoded flag: \n{flag}")
        
if __name__ == "__main__":
    ctf3("shifted.txt")
   

        