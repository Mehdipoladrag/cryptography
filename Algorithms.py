import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class CryptoManager:
    def __init__(self):
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None
    def generate_symmetric_key_from_password(self, password: str, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.symmetric_key = kdf.derive(password.encode())

    def encrypt_symmetric(self, plaintext):
        if self.symmetric_key is None:
            raise ValueError("Symmetric key is not set")
        
        cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CFB8(self.symmetric_key[:16]), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()

    def decrypt_symmetric(self, ciphertext):
        if self.symmetric_key is None:
            raise ValueError("Symmetric key is not set")
        
        ciphertext = base64.b64decode(ciphertext)
        cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CFB8(self.symmetric_key[:16]), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    def generate_asymmetric_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt_asymmetric(self, plaintext):
        if self.public_key is None:
            raise ValueError("Public key is not set")
        
        ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    def decrypt_asymmetric(self, ciphertext):
        if self.private_key is None:
            raise ValueError("Private key is not set")
        
        ciphertext = base64.b64decode(ciphertext)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()