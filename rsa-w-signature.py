
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from time import time
import os
#BASE is the directory where this script is located
BASE = os.path.dirname(os.path.abspath(__file__))
# Most of the module used is from the PyCryptodome, example documentation found at
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa

# function to generate a new RSA key pair and save them to files
# 1024-bit key pair
def generate_key_pair_1024(public_key_file, private_key_file):
    # using RSA algorithm
    key = RSA.generate(1024)
    # Save the keys to seperate files
    with open(private_key_file, "wb") as f:
        f.write(key.export_key())
    with open(public_key_file, "wb") as f:
        f.write(key.publickey().export_key())
# 2048-bit key pair
def generate_key_pair_2048(public_key_file, private_key_file):
    # using RSA algorithm
    key = RSA.generate(2048)
    # Save the keys to seperate files
    with open(private_key_file, "wb") as f:
        f.write(key.export_key())
    with open(public_key_file, "wb") as f:
        f.write(key.publickey().export_key())

# encryption function using RSA
def encrypt_rsa(plain_text_file, public_key_file):
    # Load the public key
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    # Load plaintext
    with open(plain_text_file, "rb") as f:
        plaintext = f.read()
    # Encrypt the plaintext using OAEP padding with SHA256
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# signature functions
# reference: https://www.pycryptodome.org/src/signature/pkcs1_pss
## sign function with private key
def sign_data(plaintext, private_key_file):
    key = RSA.import_key(open(private_key_file, 'rb').read())
    data = SHA256.new(bytes(plaintext, 'utf-8'))
    signature = pss.new(key).sign(data)
    return signature
## verify function
def verify_signature(plaintext_decrypted, signature, public_key_file):
    key = RSA.import_key(open(public_key_file, 'rb').read())
    data = SHA256.new(plaintext_decrypted)
    verifier = pss.new(key)
    try:
        verifier.verify(data, signature)
        return "File is authentic."
    except (ValueError, TypeError):
        return "File is not authentic."

# decryption function
def decrypt_rsa(ciphertext_file, private_key_file):
    # Read the encrypted data
    with open(ciphertext_file, "rb") as file:
        ciphertext = file.read()
    # Load the private key
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    # Decrypt the ciphertext
    # Decrypt using OAEP padding with SHA256
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    plaintext_decrypted = cipher.decrypt(ciphertext)
    return plaintext_decrypted


# main function to do the flow of the program
def main():
    # Generate a new RSA key pair and save them to files
    # Test both 1024-bit and 2048-bit keys
    key_sizes = [1024, 2048]
    results = []
    for key_size in key_sizes:
        encryption_time = 0
        decryption_time = 0
        print(f"--------Running main function on generated {key_size}-bit key----------")
        # Generate keys base on the key size. used declared key gen functions
        if key_size == 1024:
            generate_key_pair_1024(
                os.path.join(BASE, "keys", "keygen1024.pub"),
                os.path.join(BASE, "keys", "keygen1024")
            )
            public_key_file = os.path.join(BASE, "keys", "keygen1024.pub")
            private_key_file = os.path.join(BASE, "keys", "keygen1024")
        else:
            generate_key_pair_2048(
                os.path.join(BASE, "keys", "keygen2048.pub"),
                os.path.join(BASE, "keys", "keygen2048")
            )
            public_key_file = os.path.join(BASE, "keys", "keygen2048.pub")
            private_key_file = os.path.join(BASE, "keys", "keygen2048")

        # Path to files for lazy access :)
        original_txt = os.path.join(BASE, "input", "another.secret.txt")
        encrypted_file = os.path.join(BASE, "output", "encrypted_rsa")
        decrypted_file = os.path.join(BASE, "output", "decrypted_rsa")
        # Load provided plaintext
        with open(original_txt, "rt") as f:
            plaintext = f.read()
        # Encrypt the plaintext
        start_time = time() # encryption timer
        ciphertext = encrypt_rsa(original_txt, public_key_file)
        end_time = time() # encryption timer
        encryption_time = end_time - start_time
        # Save the encrypted ciphertext to a file
        with open(encrypted_file, "wb") as f:
            f.write(ciphertext)
        # Sign the plaintext
        signature = sign_data(plaintext, private_key_file)
        # decrypt the ciphertext
        start_time = time() # decryption timer
        decrypted_plaintext = decrypt_rsa(encrypted_file, private_key_file)
        end_time = time() # decryption timer
        decryption_time = end_time - start_time
        # Verify the signature of the decrypted text using the public key
        print( 'SIGNATURE VERIFICATION: ', verify_signature(decrypted_plaintext, signature, public_key_file))
        # Save the decrypted plaintext to a file
        with open(decrypted_file, "wt") as f:
            f.write(decrypted_plaintext.decode('utf-8'))
        # maesure the time taken to do the task in minutes for 1024 and 2048 key pairs.
        # Print the timing results
        # print(f"Encryption time for {key_size}-bit key: {encryption_time:.5f} seconds")
        # print(f"Decryption time for {key_size}-bit key: {decryption_time:.5f} seconds")
        # Append the results to the table
        results.append([key_size, encryption_time, decryption_time])

# tabular format without the need to install extra tabulate module(s)

    print("\nEncryption and Decryption Times:")
    print(f"{'Key Size':<10} {'Encryption Time (s)':<25} {'Decryption Time (s)':<25}")
    print("-" * 60)
    for result in results:
        print(f"{result[0]:<10} {result[1]:<25.5f} {result[2]:<25.5f}")

if __name__ == "__main__":
    main()
    