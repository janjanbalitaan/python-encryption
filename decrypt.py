import os
import base64

from utilities.rsa import RSA
from utilities.generic import Generic

# initialize utilities
rsa_utils = RSA()
g_utils = Generic()

private_key_file = None
while not private_key_file:
    private_key_file = input("Private Key File: ")
    if not os.path.exists(private_key_file):
        private_key_file = None

encrypted_text = None
while not encrypted_text:
    encrypted_text = input("Text in Base64 Format to Decrypt: ")
# encrypted_text_bytes = str.encode(encrypted_text or "", 'utf-8')
encrypted_text_bytes = base64.b64decode(encrypted_text)

priv = rsa_utils.get_private_key_by_file(
    file=private_key_file
)

decrypted_text = rsa_utils.decrypt_message(
    private_key=priv,
    encrypted_message=encrypted_text_bytes,
)

print(f'Decrypted Text: {decrypted_text.decode("utf-8")}')