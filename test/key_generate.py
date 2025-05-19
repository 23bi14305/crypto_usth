from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import rsa
import hmac
import hashlib
import secrets
import os


#AES
def generate_aes_key(length=32):
    return os.urandom(length)  # 32 bytes = 256 bits

# Function to AES encrypt a plaintext message
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # AES block size for CBC is 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext  # Return both IV and ciphertext

# Function to AES decrypt a ciphertext message
def aes_decrypt(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

def get_public_key(identifier):
    """Return an rsa.PublicKey object for the given identifier."""
    with open('public_keys.pem', 'rb') as file:
        content = file.read().decode('utf-8')
        keys = content.split("\n\n")  # Splitting based on double new lines
        for key in keys:
            if identifier in key:
                pem_str = key.split(":\n")[1]  # Extract PEM string
                return rsa.PublicKey.load_pkcs1(pem_str.encode('utf-8'), format='PEM')
    return None

    return None

def get_private_key(filename):
    """Load a private RSA key from a PEM file."""
    try:
        with open(filename, 'rb') as key_file:
            private_key = rsa.PrivateKey.load_pkcs1(key_file.read(), format='PEM')
        return private_key
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return None
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None
        
def get_hmac_key(user):
    try:
        with open(f'hmac_key_{user}.bin', 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"HMAC key for {user} not found.")
        return None
    
def generate_hmac(key, message):
    iv, ciphertext = message
    message_bytes = iv + ciphertext
    return hmac.new(key, message_bytes, hashlib.sha256).digest()

def verify_hmac(key, message, hmac_value):
    expected_hmac = generate_hmac(key, message)
    return hmac.compare_digest(expected_hmac, hmac_value)
# RSA signing and verification
def sign_message(message, private_key):
    message_hash = hashlib.sha256(message).digest()
    signature = rsa.sign(message, private_key, 'SHA-256')
    return signature
def verify_signature(message, signature, public_key):
    try:
        rsa.verify(message, signature, public_key)
        return True
    except rsa.VerificationError:
        return False
if __name__ == "__main__":         
    # Generate RSA keys
    (public_key_A, private_key_A) = rsa.newkeys(2048)
    (public_key_B, private_key_B) = rsa.newkeys(2048)
    (public_key_C, private_key_C) = rsa.newkeys(2048)


    # Store all public keys in one file with identifiers
    with open('public_keys.pem', 'wb') as pub_file:
        pub_file.write(b"Public Key A:\n" + public_key_A.save_pkcs1('PEM') + b"\n")
        pub_file.write(b"Public Key B:\n" + public_key_B.save_pkcs1('PEM') + b"\n")
        pub_file.write(b"Public Key C:\n" + public_key_C.save_pkcs1('PEM') + b"\n")

    # Store private keys separately
    with open('private_key_A.pem', 'wb') as priv_file_A:
        priv_file_A.write(private_key_A.save_pkcs1('PEM'))

    with open('private_key_B.pem', 'wb') as priv_file_B:
        priv_file_B.write(private_key_B.save_pkcs1('PEM'))

    with open('private_key_C.pem', 'wb') as priv_file_C:
        priv_file_C.write(private_key_C.save_pkcs1('PEM'))


    # Generate HMAC keys for A, B, and C
    hmac_keys = {
        "A": secrets.token_bytes(32),
        "B": secrets.token_bytes(32),
        "C": secrets.token_bytes(32)
    }

    # Save each key in a separate file
    for user, key in hmac_keys.items():
        with open(f'hmac_key_{user}.bin', 'wb') as key_file:
            key_file.write(key)


    print("HMAC keys generated and stored securely.")
