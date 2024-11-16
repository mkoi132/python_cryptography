#RSA calculation algorithm Overall steps:
# Generating p, q (p and q both prime and p not equal to q)
# Calculate n = p * q
# Calculate totient, r = (p -1) * (q — 1)
# Choose e such that 1 < e < r and gcd (e,r) =1
# Compute a value for d = e ^-1 mod (r)
# Consider e as Public Key and d as a Private Key.
# For encryption, Cipher Text = (Message ^ e) % n (where, Message < n)
# For decryption, Message = (Cipher Text ^ d) % n

# Some math libraries that make our life easier
import secrets
import math as m
import random
import os
#BASE is the directory where this script is located
BASE = os.path.dirname(os.path.abspath(__file__))
# Generating p and q both prime and p not equal to q
# function that check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    # this method is inspired from the solution https://www.codecademy.com/forum_questions/5197bdaf9b22072db500228d
    # isqrt() method returns the possitive integer square root of number n https://docs.python.org/3/library/math.html#math.isqrt
    # i range from 2 up to the square root of n, including it
    for i in range(2, m.isqrt(n) + 1):  
        # check if n is divisible by any i
        #if remainder is 0, then n is not a prime number
        if n % i == 0:
            return False
    return True
# function to generate 2 prime numbers (with bit length)
def generate_primes():
    primes = []
    while len(primes) < 2: #generate 2 prime numbers
        #this function generates a random positive integer with k bits length
        #i choose 32 bits for lightweight calculation, my computer could not handle larger bit length.
        #reference: https://docs.python.org/3/library/secrets.html#secrets.randbits
        n = secrets.randbits(32)
        if is_prime(n) and n not in primes: # then check if n is prime and not identical to the other in list
            primes.append(n)
    return primes


# RSA encryption function
def encrypt_rsa(input_plaintxt_file, output_data_path, output_key_path):
    # Generate p and q 
    p, q = generate_primes()
    # Calculate public key n
    n = p * q
    # Calculate totient, t = (p -1) * (q — 1)
    r = (p - 1) * (q - 1)
    # Choose second public key e such that 1 < e < r and gcd (e,r) =1
    # gcd function returns greatest common divisor of 2 int argumnents. reference: https://docs.python.org/3/library/math.html#math.gcd
    e = random.randrange(1, r) 
    # check if e is coprime with r
    while m.gcd(e, r) != 1:  # Loop until found e coprime with r, gcd(e,r) == 1, stop when found.
        e = random.randrange(1, r)  # Generate a new random integer for each irteration
    # pow() function returns the value of (x^y), and optional third value for modulo calculation.
    # reference: https://docs.python.org/3/library/functions.html#pow
    #  private key d = e^-1 mod (r)
    d= pow(e, -1, r)
        # Load plaintext from file
    with open(input_plaintxt_file, "r") as f:
        message = f.read()
    # convert message to integer, int() is optimal for this case.
    message = int(message)
    # if the message is an actual letter, it could be converted to integer using ord() function
    # then converted back to letter using chr() function after decryption.
    #encrypt the message using both public keys
    #Ciphertext = (Message ^ e) % n
    c = pow(message, e, n)
    #export public and private key pair to the folder specified in the keys_path
    with open(os.path.join(output_key_path, "manual_rsa_key.pub"), "w") as f:
        f.write(str(n))
    with open(os.path.join(output_key_path, "manual_rsa_key"), "w") as f:
        f.write(str(d))
    # Write ciphertext to a file
    with open(os.path.join(output_data_path, "manual_rsa_ciphertext.txt"), "w") as f:
        f.write(str(c))

# RSA decryption function
def rsa_decrypt(encrypted_file, key_pub, key_priv, decrypted_output_path):
    # Read the encrypted data and keys'
    # save them to variables
    with open(encrypted_file, "r") as file:
        c = int(file.read())
    with open(key_pub, "r") as f:
        n = int(f.read())
    with open(key_priv, "r") as f:
        d = int(f.read())
    #Peforming the decryption calculation using the rsa formula
    #Decrypted plain text = (Cipher Text ^ d) % n
    pt = pow(c, d, n)
    # Write decrypted message to a file
    with open(os.path.join(decrypted_output_path, "manual_rsa_decrypt.txt"), "w") as f:
        f.write(str(pt))



# call the encrypt function and specify the required parameters
encrypt_rsa(input_plaintxt_file=os.path.join(BASE, "input", "secret_numb.txt"),
            output_data_path=os.path.join(BASE, "output"),
            output_key_path=os.path.join(BASE, "keys"))

# call the decrypt function and specify the required files
rsa_decrypt(encrypted_file=os.path.join(BASE, "output", "manual_rsa_ciphertext"),
            key_pub=os.path.join(BASE, "keys", "manual_rsa_key.pub"),
            key_priv=os.path.join(BASE, "keys", "manual_rsa_key"),
            decrypted_output_path=os.path.join(BASE, "output"))
