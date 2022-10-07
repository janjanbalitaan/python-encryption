from typing import Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import serialization, hashes # type: ignore
from cryptography.exceptions import InvalidSignature # type: ignore
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey

class RSA:

    def get_private_key_by_file(
        self,
        file: str,
        password: Optional[bytes] = None,
    ) -> _RSAPrivateKey:
        with open(file, "rb") as key_file:
            key_bytes: bytes = key_file.read()
        
        return self.get_private_key_by_key_bytes(key_bytes=key_bytes, password=password)

    def get_private_key_by_key_bytes(
        self,
        key_bytes: bytes,
        password: Optional[str] = None,
    ) -> _RSAPrivateKey:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None if not password else password
        )
        
        return private_key

    def generate_private_key(
        self,
        public_exponent: int = 65537,
        key_size: int = 2048,
    ) -> bytes:
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )

        return private_key

    def get_private_key_pem(
        self,
        private_key: _RSAPrivateKey,
        encoding: Optional[Any] = serialization.Encoding.PEM,
        format: Optional[Any] = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm: Optional[Any] = serialization.NoEncryption(),
    ) -> bytes:

        pem = private_key.private_bytes(
            encoding=encoding,
            format=format,
            encryption_algorithm=encryption_algorithm
        )

        return pem

    def get_public_key_by_file(
        self,
        file: str,
    ) -> _RSAPublicKey:
        with open(file, "rb") as key_file:
            key_bytes: bytes = key_file.read()
        
        return self.get_public_key_by_key_bytes(key_bytes=key_bytes)

    def get_public_key_by_key_bytes(
        self,
        key_bytes: bytes,
    ) -> _RSAPublicKey:
        public_key = serialization.load_pem_public_key(
            key_bytes,
        )
        
        return public_key

    def get_public_key(
        self, 
        private_key: _RSAPrivateKey
    ) -> _RSAPublicKey:
        public_key = private_key.public_key()
        return public_key

    def get_public_key_pem(
        self,
        public_key: _RSAPublicKey,
        encoding: Optional[Any] = serialization.Encoding.PEM,
        format: Optional[Any] = serialization.PublicFormat.SubjectPublicKeyInfo,
    ) -> bytes:
        pem = public_key.public_bytes(
            encoding=encoding,
            format=format,
        )

        return pem

    def sign_message(
        self,
        private_key: _RSAPrivateKey,
        message: bytes,
        algorithm: Any = hashes.SHA256(),
        salt_length: int = padding.PSS.MAX_LENGTH
    ) -> bytes:
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm),
                salt_length=salt_length,
            ),
            algorithm
        )

        return signature

    def verify_message(
        self,
        public_key: _RSAPublicKey,
        signature: bytes,
        message: bytes,
        algorithm: Any = hashes.SHA256(),
        salt_length: int = padding.PSS.MAX_LENGTH
    ) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(algorithm),
                    salt_length=salt_length,
                ),
                algorithm
            )
        except InvalidSignature:
            return False
        except Exception:
            return False


        return True

    def encrypt_message(
        self,
        public_key: _RSAPublicKey,
        message: bytes,
        algorithm: Any = hashes.SHA256(),
        label: bytes = None,
    ) -> bytes:
        encrypted_message = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=algorithm),
                algorithm=algorithm,
                label=label,
            )
        )

        return encrypted_message

    def decrypt_message(
        self,
        private_key: _RSAPrivateKey,
        encrypted_message: bytes,
        algorithm: Any = hashes.SHA256(),
        label: Optional[bytes] = None,
    ) -> bytes:
        message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=algorithm),
                algorithm=algorithm,
                label=label,
            )
        )

        return message
