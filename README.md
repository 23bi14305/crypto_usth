# crypto_usth

# IMPORTANT
- main code inside the folder final
- to run the code, $python main.py
- libary needed: cryptography, rsa, hashlib

# MAIN PROBLEM
- Scalability
- Group n member, a sender need to send (n - 1) packets (enc_aes_key, cipher, signature) to the server, then server distributes to corresponding members (need to mark the packet to correct member)
- Temporary solution: since (cipher, signature), send only 1 time, then send (n - 1) times the (enc_aes_key) to the server (reduce the packet size)

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


# run demo
run main.py

# all_function.py
- include necessary function

# pack
(testing...)
# test dir
test the flow
- $python key_generate.py
- $python test_rsa_signature.py
