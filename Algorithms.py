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
    def save_asymmetric_keys(self, private_key_path, public_key_path):
        if self.private_key is None or self.public_key is None:
            raise ValueError("Asymmetric keys are not set")
        
        try:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(private_key_path, 'wb') as f:
                f.write(pem)
            
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(public_key_path, 'wb') as f:
                f.write(pem)
            
            print(f"Keys saved successfully to {private_key_path} and {public_key_path}")
        except Exception as e:
            print(f"Error saving keys: {e}")

    def load_asymmetric_keys(self, private_key_path, public_key_path):
        try:
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            self.private_key = private_key

            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            self.public_key = public_key

            print(f"Keys loaded successfully from {private_key_path} and {public_key_path}")
        except Exception as e:
            print(f"Error loading keys: {e}")


if __name__ == "__main__":
    manager = CryptoManager()
    

    password = input("Enter your password for symmetric encryption: ")
    salt = os.urandom(16)  

    manager.generate_symmetric_key_from_password(password, salt)
    symmetric_message = input("Enter a message to encrypt with symmetric encryption: ")
    encrypted_message_symmetric = manager.encrypt_symmetric(symmetric_message)
    print(f"Encrypted symmetric message: {encrypted_message_symmetric}")
    decrypted_message_symmetric = manager.decrypt_symmetric(encrypted_message_symmetric)
    print(f"Symmetric Decryption: {decrypted_message_symmetric}")


    manager.generate_asymmetric_keys()
    asymmetric_message = input("Enter a message to encrypt with asymmetric encryption: ")
    encrypted_message_asymmetric = manager.encrypt_asymmetric(asymmetric_message)
    print(f"Encrypted asymmetric message: {encrypted_message_asymmetric}")
    decrypted_message_asymmetric = manager.decrypt_asymmetric(encrypted_message_asymmetric)
    print(f"Asymmetric Decryption: {decrypted_message_asymmetric}")


    manager.save_asymmetric_keys('private_key.pem', 'public_key.pem')
    manager.load_asymmetric_keys('private_key.pem', 'public_key.pem')