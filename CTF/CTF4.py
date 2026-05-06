from PIL import Image

def extract_lsb_flag(image_path):
    print(f"[*] Opening target image: {image_path}")
    try:
        img = Image.open(image_path)
    except FileNotFoundError:
        print(f"[!] Error: Could not find '{image_path}'. Check your spelling and folder path!")
        return

    
    pixels = img.load()
    width, height = img.size

    print(f"[*] Image Mode: {img.mode}")
    print("[*] Extracting Least Significant Bits (Grayscale optimized)...")
    extracted_bits = ""
    
    # 1. Read every pixel from top-left to bottom-right
    for y in range(height):
        for x in range(width):
            pixel = pixels[x, y]
            
            # Since the image is grayscale, R, G, and B are identical.
            # We only need to extract the LSB of the FIRST channel (Red).
            r = pixel
            extracted_bits += str(r & 1)

    print("[*] Grouping bits into bytes and translating to ASCII (Full Image Scan)...")
    extracted_text = ""
    
    # 2. Group every 8 bits into a byte
    for i in range(0, len(extracted_bits), 8):
        byte = extracted_bits[i:i+8]
        
        # Make sure we have a full 8-bit byte
        if len(byte) == 8:
            char_code = int(byte, 2)
            
            # We removed the 'break' on char_code == 0 so it scans the whole image
            
            # Only append standard printable ASCII characters
            if 32 <= char_code <= 126 or char_code in (9, 10, 13):
                extracted_text += chr(char_code)

    print("[*] Scan complete. Searching for flag pattern...")
    
    # 3. Look for the known CTF flag format in the extracted text
    if "CMPN{" in extracted_text:
        start_index = extracted_text.find("CMPN{")
        end_index = extracted_text.find("}", start_index) + 1
        
        print("\n" + "="*50)
        print("FLAG SUCCESSFULLY EXTRACTED:")
        print(extracted_text[start_index:end_index])
        print("="*50 + "\n")
    else:
        print("\n[!] Flag format 'CMPN{' not found. Here is a snippet of the raw extracted text:")
        print(extracted_text[:500])

if __name__ == "__main__":
    # Ensure this points to the correct location of your stego image
    extract_lsb_flag("CTF/stego.png")