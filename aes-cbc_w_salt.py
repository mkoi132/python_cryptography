
# importing necessary modules
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os
import os.path

#   setting the base directory for file paths
BASE = os.path.dirname(os.path.abspath(__file__))


# function to encrypt a plain text file and produce an encrypted file
def encrypt_file(input_file_path, output_file_path, password):

    # generate random salt for key derivation function
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, #32 byte key for 256 bit encryption
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode()) # Derive the encryption key from the password

    # generate a random initialization vector (IV) for AES-CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # read input file
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()

    # adding padding to ensure the plaintext is a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # encrypt the plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Display the key and encrypted output in hex format
    print(f"Key (hex): {key.hex()}")
    print('─' * 10)
    print(f"Encrypted Output (hex): {ciphertext.hex()}")
    # write the salt, IV, and ciphertext to the output file
    with open(output_file_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)


# Function to decrypt the encrypted file.
def decrypt_file(input_file_path, output_file_path, password):

    # read input file
    with open(input_file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # derive the decryption key using the same KDF parameters (must match encryption)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode()) # Derive the decryption key 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # decrypt ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()


    # Display the decrypted output 
    print(f"Decrypted Output: {plaintext.decode('utf-8')}")
    # write the decrypted plaintext to the output file
    with open(output_file_path, 'wt') as f:
        f.write(plaintext.decode('utf-8'))



# Call the encryption function
print('─' * 10)
encrypt_file(BASE + '/input/secret.txt', BASE + '/output/aes_enc', 'p@33w0rd')

print('─' * 10)
# Call the decryption function
decrypt_file(BASE + '/output/aes_enc', BASE + '/output/aes_dec', 'p@33w0rd')

print('─' * 10)
