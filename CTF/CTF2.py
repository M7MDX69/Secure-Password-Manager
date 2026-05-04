from PIL import Image
import numpy as np

print("[*] Opening layers...")
# 1. Open the two images
img1 = Image.open('CTF/Layer1.png')
img2 = Image.open('CTF/Layer2.png')

# 2. Convert images to arrays of numbers so NumPy can do the math
arr1 = np.array(img1)
arr2 = np.array(img2)

print("[*] Performing bitwise XOR on pixels...")
# 3. Perform the bitwise XOR operation
# This compares the binary value of every single pixel overlapping between the two images.
# Where the noise is identical, it cancels out (becomes black). 
# Where the secret flag text was embedded, it will stand out!
result_arr = np.bitwise_xor(arr1, arr2)

# 4. Convert the resulting numbers back into an image
result_img = Image.fromarray(result_arr)

print("[*] Saving and opening the result...")
# 5. Save the revealed flag and pop it open on your screen
result_img.save('CTF/ctf2_flag.png')
result_img.show()