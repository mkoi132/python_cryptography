
# import necessary cryptography libraries for rsa and padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom, path
import os

# setting the base directory for file paths
BASE = os.path.dirname(os.path.abspath(__file__))

# function to generate rsa public and private keys using cryptography rsa module
def generate_rsa_keys():
    # create a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # deriving the public key from the private key
    public_key = private_key.public_key()

    # this implementation uses the key serialization modules to convert the keys to pem format
    #https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/#key-serialization

    # https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.private_bytes
    # save private key to file
    with open(BASE + "task4_private_key.pem", "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.public_bytes
    # savie public key to file
    with open(BASE + "task4_public_key.pem", "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    # returning the generated keys
    return private_key, public_key

# function to encrypt a file using hybrid encryption
def hybrid_encrypt_file(input_file_path, output_file_path, public_key):
    # generating random aes key and initialization vector for symmetric encryption
    symmetric_key = urandom(32)
    iv = urandom(16)
    # setting up aes encryption using cbc mode
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # reading the input file content for plain text message
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    # add padding the plaintext to match aes block size using pkcs7 padding algorithm
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    # encrypting the padded plaintext
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    # # printing encrypted message
    # print(f"Encrypted Message (hex): {encrypted_message.hex()}")

    # encrypting the symmetric key using rsa and oaep padding
    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # writing iv, encrypted key, and encrypted message to one single output file
    with open(output_file_path, 'wb') as f:
        f.write(iv)
        f.write(encrypted_key)
        f.write(encrypted_message)

# function to decrypt the encrypted file
def hybrid_decrypt_file(input_file_path, output_file_path, private_key):
    # reading the encrypted file content
    # identify the iv, encrypted key, and encrypted message
    with open(input_file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_key = f.read(256)
        encrypted_message = f.read()

    # decrypting the encrypted symmetric key using rsa
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # setting up aes decryption object using cbc mode
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # decrypting the encrypted message, we get the padded plaintext
    padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
    # unpadding the plaintext to retrieve the original content
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    # writing the decrypted plaintext to the output file
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)

# rsa keys generation using the function defined above
private_key, public_key = generate_rsa_keys()

# defining file paths for input, encrypted output, and decrypted output
input_file_path = BASE + '/input/secret.txt'
encrypted_file_path = BASE + '/output/hybrid_encrypted'
decrypted_file_path = BASE + '/output/hybrid_decrypted.txt'

# calling the encryption function with the input file path, output file path, and public key
hybrid_encrypt_file(input_file_path, encrypted_file_path, public_key)

# calling the decryption function with the encrypted file path, output file path, and private key
hybrid_decrypt_file(encrypted_file_path, decrypted_file_path, private_key)
