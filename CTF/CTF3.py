def ctf3(filename):
    
    print(f"[*] Reading file: {filename}")
    
    
    with open(filename, 'r') as f:
        extracted_data = f.read().split()
    
    
    final_flag = ""
    
    for number_string in extracted_data:
        
        #convert text string into actual integer
        shifted_value = int(number_string)
        
        #reverse left shift by right shifting
        
        original_value = shifted_value >> 1
        
        #convert the ascii decimal back to text
        
        ascii_character = chr(original_value)
        
        final_flag += ascii_character
        
    print(f"\n[+] Decoded flag: \n{final_flag}")
        
if __name__ == "__main__":
    ctf3("shifted.txt")
   

        