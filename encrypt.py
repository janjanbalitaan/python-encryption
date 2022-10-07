import os
import base64

from utilities.rsa import RSA
from utilities.generic import Generic

# initialize utilities
rsa_utils = RSA()
g_utils = Generic()

public_key_file = None
while not public_key_file:
    public_key_file = input("Public Key File: ")
    if not os.path.exists(public_key_file):
        public_key_file = None

plain_text = None
while not plain_text:
    plain_text = input("Text to Encrypt: ")
plain_text_bytes = str.encode(plain_text or "", 'utf-8')

pub = rsa_utils.get_public_key_by_file(
    file=public_key_file
)

encrypted_text = rsa_utils.encrypt_message(
    public_key=pub,
    message=plain_text_bytes,
)
encrypted_text_b64 = base64.b64encode(encrypted_text)
print(f'Encrypted Text Base64: {encrypted_text_b64.decode("utf-8")}')
