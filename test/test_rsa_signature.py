from test_gen_key import *
import rsa
import os
if __name__ == "__main__":
    # A generate AES key
    print("### A generated AES key")

    aes_key = generate_aes_key()
    print("AES key length:", len(aes_key))
    print("AES key:", aes_key)



    
    print("### A send cipher")

    message_A = b"Hello from A"
    print("message_A: ", message_A)

    # A sign
    print("### A sign")
    private_key_A = get_private_key("private_key_A.pem")
    signature_A = sign_message(message_A, private_key_A)
    print("Signature:", signature_A.hex())
    # A encrypt
    encrypted_message_A = aes_encrypt(message_A, aes_key)
    print("Encrypted message:", encrypted_message_A)



    # A send aes_key
    public_key_B = get_public_key("Public Key B")
    public_key_C = get_public_key("Public Key C")

    encrypted_aes_key_B = rsa.encrypt(aes_key, public_key_B)
    encrypted_aes_key_C = rsa.encrypt(aes_key, public_key_C)

    
    print("encrypted_aes_key B:", encrypted_aes_key_B)
    print("encrypted_aes_key C:", encrypted_aes_key_C)

    print("### Sending...")



    # B decrypt
    print("### B decrypt")
    private_key_B = get_private_key("private_key_B.pem")
    decrypted_aes_key = rsa.decrypt(encrypted_aes_key_B, private_key_B)
    print("decrypted_aes_key:", decrypted_aes_key.hex())
    decrypted_message_A = aes_decrypt(*encrypted_message_A, decrypted_aes_key)
    print("decrypted_message_A:", decrypted_message_A.decode())
    # B verify signature
    print("### B verify signature_A")
    public_key_A = get_public_key("Public Key A")
    if verify_signature(decrypted_message_A, signature_A, public_key_A):
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")
    


    # C decrypt
    print("### C decrypt")
    private_key_C = get_private_key("private_key_C.pem")
    decrypted_aes_key = rsa.decrypt(encrypted_aes_key_C, private_key_C)
    print("decrypted_aes_key:", decrypted_aes_key.hex())
    decrypted_message_A = aes_decrypt(*encrypted_message_A, decrypted_aes_key)
    print("decrypted_message_A:", decrypted_message_A.decode())
    
    # C verify signature
    print("### C verify signature_A")   
    public_key_A = get_public_key("Public Key A")
    if verify_signature(decrypted_message_A, signature_A, public_key_A):
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")
