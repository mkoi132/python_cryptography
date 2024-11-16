
#importing relevant libraries
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
#os to handle BASE operations
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os.path
#BASE is the directory where this script is located
BASE=os.path.dirname(os.path.abspath(__file__))

# given encrypted variables in hex-coded string
CBC_key = "140b41b22a29beb4061bda66b6747e14"
CBC_ciphertext=  "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
# convert them to byte so they fits the decrypt function
# reference could be found at: https://docs.python.org/3/library/stdtypes.html#bytes.fromhex
CBC_key_b = bytes.fromhex(CBC_key)
CBC_ciphertext_b = bytes.fromhex(CBC_ciphertext)

# function to decypt form pycryptodome library documentation
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode

def decrypt_file(key, output_file_path):
    # Initialization vector (IV) - the first 16 bytes of the ciphertext
    iv = CBC_ciphertext_b[:16]  ## first 16 bytes of the ciphertext
    ciphertext = CBC_ciphertext_b[16:] ## the rest of the ciphertext
    # Create AES cipher object with the key and vi using CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext
    plain_txt_padded = cipher.decrypt(ciphertext)
    plain_txt_unpadded = unpad(plain_txt_padded, AES.block_size)
    # Write the decrypted text to the output file path
    with open(output_file_path, 'wt') as file_out:
        file_out.write(plain_txt_unpadded.decode('utf-8'))

# call decryption function 
# Pass on the key value, and the output file path.
decrypt_file( CBC_key_b, BASE  + '/output/decrypt_from_aes_cbc')
print("Great! Message recovered at: " + BASE + '/output/decrypt_from_aes_cbc') 