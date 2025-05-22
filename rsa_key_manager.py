import os
import rsa
from datetime import datetime, timedelta

KEY_EXPIRY_TIME = timedelta(hours=1)

def get_key_paths(username):
    pub_path = f'public_key_{username}.pem'
    priv_path = f'private_key_{username}.pem'
    meta_path = f'key_meta_{username}.txt'
    return pub_path, priv_path, meta_path

def is_key_expired(meta_path):
    if not os.path.exists(meta_path):
        return True
    with open(meta_path, 'r') as f:
        timestamp = f.read().strip()
        last_generated = datetime.fromisoformat(timestamp)
        if datetime.utcnow() - last_generated > KEY_EXPIRY_TIME:
            return True
    return False

def generate_and_store_keys(username):
    (pub_key, priv_key) = rsa.newkeys(2048)
    pub_path, priv_path, meta_path = get_key_paths(username)
    with open(pub_path, 'wb') as f:
        f.write(pub_key.save_pkcs1('PEM'))
    with open(priv_path, 'wb') as f:
        f.write(priv_key.save_pkcs1('PEM'))
    with open(meta_path, 'w') as f:
        f.write(datetime.utcnow().isoformat())

def ensure_fresh_rsa_key(username):
    pub_path, priv_path, meta_path = get_key_paths(username)
    if is_key_expired(meta_path):
        print(f"[{username}] Key expired or missing — generating new RSA key pair.")
        generate_and_store_keys(username)
    else:
        print(f"[{username}] Existing key is valid — using existing RSA keys.")

