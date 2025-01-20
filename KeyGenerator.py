import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class KeyGenerator:
    def __init__(self):
        self.symmetric_key = None
        self.generate_symmetric_key()

    def generate_symmetric_key(self):
        self.symmetric_key = secrets.token_hex(32)

    def get_symmetric_key(self):
        return self.symmetric_key



