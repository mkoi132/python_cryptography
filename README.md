# Quick start
Scripts support python 3.10 and later
Before you can run any script, in the project directory, execute `pip install -r requirement.txt`. This will install neccesacry libraries to peform the task.

- `aes-cbc_w_salt` script implements file encryption and decryption using AES (Advanced Encryption Standard) with CBC (Cipher Block Chaining) mode using the cryptography library for cryptographic operations and key derivation.
- `decrypt_aes_cbc` script decrypts a given AES-encrypted message in CBC (Cipher Block Chaining) mode using the pycryptodome library.
- `hybrid-encryption`script implements Hybrid Encryption, combining RSA (asymmetric encryption) and AES (symmetric encryption) to securely encrypt and decrypt files.
- `rsa-manual` script implements the basic RSA algorithm manually using the RSA calculation formula
- `rsa-w-signature` script encrypts and decrypts data using the RSA algorithm with generated RSA key pairs (in both 1024-bit and 2048-bit), it also implement signature and verification to the decrypted data.

# Notes
Scripts could be run in terminal using command `python + {script_name}.py`, inputs and output file paths can be easily adjusted, see comments for each script.
Keys folder contains generated keypairs as the script run. Key pairs should be treated as secret and not to be uploaded to project repository.

