from test_gen_key import *
import rsa
import os
if __name__ == "__main__":
    # A generate AES key
    print("### A generated AES key")

    aes_key = generate_aes_key()
    print("AES key length:", len(aes_key))
    print("AES key:", aes_key)

    # A encrypt
    print("### A send cipher")

    message_A = b"Hello from A"
    print("message_A: ", message_A)
    encrypted_message_A = aes_encrypt(message_A, aes_key)
    print("Encrypted message:", encrypted_message_A)

    # A sign
    print("### A sign")
    hmac_key_A = get_hmac_key("A")
    hmac_value_A = generate_hmac(hmac_key_A, encrypted_message_A)
    print("HMAC value:", hmac_value_A.hex())

    # A send aes_key
    public_key_B = get_public_key("Public Key B")
    public_key_C = get_public_key("Public Key C")

    encrypted_aes_key_B = rsa.encrypt(aes_key, public_key_B)
    encrypted_aes_key_C = rsa.encrypt(aes_key, public_key_C)

    
    print("encrypted_aes_key B:", encrypted_aes_key_B)
    print("encrypted_aes_key C:", encrypted_aes_key_C)

    print("### Sending...")


    # B verify HMAC 
    print("### B verify HMAC")
    if verify_hmac(hmac_key_A, encrypted_message_A, hmac_value_A):
        print("HMAC verified successfully.")
    else:
        print("HMAC verification failed.")
        
    # B decrypt
    print("### B decrypt")
    private_key_B = get_private_key("private_key_B.pem")
    decrypted_aes_key = rsa.decrypt(encrypted_aes_key_B, private_key_B)
    print("decrypted_aes_key:", decrypted_aes_key.hex())
    decrypted_message_A = aes_decrypt(*encrypted_message_A, decrypted_aes_key)
    print("decrypted_message_A:", decrypted_message_A.decode())

    

    # C verify HMAC
    print("### C verify HMAC")
    if verify_hmac(hmac_key_A, encrypted_message_A, hmac_value_A):
        print("HMAC verified successfully.")
    else:
        print("HMAC verification failed.")

    # C decrypt
    print("### C decrypt")
    private_key_C = get_private_key("private_key_C.pem")
    decrypted_aes_key = rsa.decrypt(encrypted_aes_key_C, private_key_C)
    print("decrypted_aes_key:", decrypted_aes_key.hex())
    decrypted_message_A = aes_decrypt(*encrypted_message_A, decrypted_aes_key)
    print("decrypted_message_A:", decrypted_message_A.decode())
    
