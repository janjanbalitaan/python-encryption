from utilities.rsa import RSA
from utilities.generic import Generic

from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey

class Test:
    g_utils = Generic()
    rsa_utils = RSA()
    private_key = None
    public_key = None

    def test_private_key(self):
        try:
            key = self.rsa_utils.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            assert type(key) == _RSAPrivateKey

            pem = self.rsa_utils.get_private_key_pem(
                private_key=key,
            )
            assert type(pem) == bytes
            assert pem is not None
            assert pem != b''
        except Exception as e:
            assert False, str(e)

    def test_public_key(self):
        try:
            pk = self.rsa_utils.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            key = self.rsa_utils.get_public_key(private_key=pk)
            assert type(key) == _RSAPublicKey

            pem = self.rsa_utils.get_public_key_pem(
                public_key=key,
            )
            assert type(pem) == bytes
            assert pem is not None
            assert pem != b''
        except Exception as e:
            assert False, str(e)

    def test_signature(self):
        try:
            pk = self.rsa_utils.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            key = self.rsa_utils.get_public_key(private_key=pk)
            assert type(key) == _RSAPublicKey
            
            # sign
            text_to_sign = b'signed text'
            signature = self.rsa_utils.sign_message(
                private_key=pk,
                message=text_to_sign,
            )
            assert type(signature) == bytes
            assert signature is not None
            assert signature != b''

            # verify
            is_verified = self.rsa_utils.verify_message(
                public_key=key,
                signature=signature,
                message=text_to_sign,
            )
            assert type(is_verified) == bool
            assert is_verified == True
        except Exception as e:
            assert False, str(e)

    def test_encrypt_decrypt(self):
        try:
            pk = self.rsa_utils.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            key = self.rsa_utils.get_public_key(private_key=pk)
            assert type(key) == _RSAPublicKey
            
            # encrypt a text
            text_to_encrypt = b'encrypted text'
            encrypted_text = self.rsa_utils.encrypt_message(
                public_key=key,
                message=text_to_encrypt,
            )
            assert type(encrypted_text) == bytes
            assert encrypted_text is not None
            assert encrypted_text != b''

            # decrypt a text
            decrypted_text = self.rsa_utils.decrypt_message(
                private_key=pk,
                encrypted_message=encrypted_text,
            )
            assert type(decrypted_text) == bytes
            assert decrypted_text is not None
            assert decrypted_text != b''
            assert decrypted_text == text_to_encrypt
        except Exception as e:
            assert False, str(e)