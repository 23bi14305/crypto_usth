from rsa_key_manager import *
from all_function import *
import os  

user_list = []
user_list.append("A")
user_list.append("B")
user_list.append("C")

# Generate RSA keys for users A, B, C if not existing
for user in user_list:
    if not (os.path.exists(f'public_key_{user}.pem') and os.path.exists(f'private_key_{user}.pem')):
        ensure_fresh_rsa_key(user)
# Load keys
private_key_A = get_private_key("A")
public_key_A  = get_public_key("A")
private_key_B = get_private_key("B")
public_key_B  = get_public_key("B")
private_key_C = get_private_key("C")
public_key_C  = get_public_key("C")

# Message to send
message = b"Hello from A"
print("Original message:", message)

# AES key generation
aes_key = generate_aes_key()

# Sign the plaintext message with A's private key
signature = sign_message(message, private_key_A)

# Encrypt the message using AES
iv, ciphertext = aes_encrypt(message, aes_key)

# Encrypt AES key with B and C's public keys
enc_key_B = rsa_encrypt(aes_key, public_key_B)
enc_key_C = rsa_encrypt(aes_key, public_key_C)

# B receives and processes the message
print("\nB receives:")
aes_key_B = rsa_decrypt(enc_key_B, private_key_B)
decrypted_msg_B = aes_decrypt(iv, ciphertext, aes_key_B)
if verify_signature(decrypted_msg_B, signature, public_key_A):
    print("Decrypted:", decrypted_msg_B)
    print("Signature valid")
else:
    print("Signature invalid")

# C receives and processes the message
print("\nC receives:")
aes_key_C = rsa_decrypt(enc_key_C, private_key_C)
decrypted_msg_C = aes_decrypt(iv, ciphertext, aes_key_C)
if verify_signature(decrypted_msg_C, signature, public_key_A):
    print("Decrypted:", decrypted_msg_C)
    print("Signature valid")
else:
    print("Signature invalid")
