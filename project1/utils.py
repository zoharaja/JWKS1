# Import necessary functions
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import base64

# Stores generated keys
keys_store = {}

# Converts value to bytes and encodes to base64
def base_64(value):
    return base64.urlsafe_b64encode(
        value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')
    ).decode()

# Generates RSA keys
def generate_rsa_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key

# Stores RSA keys and returns the info
def generate_and_store_key():
    private_key = generate_rsa_key_pair()

    kid = f'key-{datetime.datetime.utcnow().isoformat()}'
    expiry = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    # Stores key information
    keys_store[kid] = {
        'private_key': private_key,
        'expiry': expiry,
        'public_key': private_key.public_key(),
        'public_numbers': private_key.public_key().public_numbers()
    }
    # Returns the key
    return kid