from utilities.rsa import RSA
from utilities.generic import Generic

from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding # type: ignore

# initialize utilities
rsa_utils = RSA()
g_utils = Generic()

# generate a private key
# this private key is an object but if you want to save it in a file you need to call rsa_utils.get_private_key_pem() to generate a bytes type of the private key
# and g_utils.save_bytes_to_file() to save to a file
private_key = rsa_utils.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
# generate public key
# this public key is an object but if you want to save it in a file you need to call rsa_utils.get_public_key_pem() to generate a bytes type of the private key 
# and g_utils.save_bytes_to_file() to save to a file
public_key = rsa_utils.get_public_key(private_key)

# sign message
text_to_sign = b'signed text'
signature = rsa_utils.sign_message(
    private_key=private_key, 
    message=text_to_sign,
    algorithm=hashes.SHA256(),
    salt_length=padding.PSS.MAX_LENGTH,
)
print(f'Signature: {signature}')

# verify signature
is_verified = rsa_utils.verify_message(
    public_key=public_key,
    signature=signature,
    message=text_to_sign,
    algorithm=hashes.SHA256(),
    salt_length=padding.PSS.MAX_LENGTH,
)
print(f'Is Signature Verified: {is_verified}')

# encrypt a text
text_to_encrypt = b'encrypted text'
encrypted_text = rsa_utils.encrypt_message(
    public_key=public_key,
    message=text_to_encrypt,
    algorithm=hashes.SHA256(),
    label=None,
)
print(f'Encrypted text: {encrypted_text}')

# decrypt a text
decrypted_text = rsa_utils.decrypt_message(
    private_key=private_key,
    encrypted_message=encrypted_text,
    algorithm=hashes.SHA256(),
    label=None
)
print(f'Decrypted text: {decrypted_text}')