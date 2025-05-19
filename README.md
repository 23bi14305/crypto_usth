# crypto_usth

# overview
Algorithm used:
- Symmetric encryption (AES) for message confidentiality.
- Asymmetric encryption (RSA) for securely exchanging the symmetric key.
- Digital signatures (RSA) for authenticity and integrity.

# Flow  
- Generated AES key to encrypt the message
- The sender signs the plaintext message, using their private RSA key to create a signature.
- Use AES key to encrypt the message
- The sender encrypts the AES key using the receiver’s public RSA key.
- The sender send the cipher text, encrypted AES key and the signature
- The receivers decrypt the AES key using their private RSA key.
- Use AES key to and decrypt the message
- The receiver verifies the signature using the sender’s public RSA key, the decrypted message, and the received signature.
  
# function.py
- include necessary function

# test dir
test the flow
- $python key_generate.py
- $python test_rsa_signature.py
