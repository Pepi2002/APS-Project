from NumberGenerator import CSPRNGGenerator
import base64
import os
from typing import Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class HybridCrypto:

    def __init__(self):
        self.csprng = CSPRNGGenerator()

    def encrypt_hybrid(self, data: bytes, recipient_public_key: RSAPublicKey) -> Dict[str, str]:
        # Genera chiave simmetrica temporanea
        session_key = self.csprng.generate_session_key()

        # Genera IV casuale per AES-CTR
        iv = os.urandom(16)

        # Cifra i dati con AES-CTR
        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Cifra la chiave di sessione con RSA-OAEP
        encrypted_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(iv).decode()
        }

    def decrypt_hybrid(self, encrypted_package: Dict[str, str],
                       recipient_private_key: RSAPrivateKey) -> bytes:
        """Decifratura ibrida"""
        # Decodifica i componenti
        encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])
        encrypted_key = base64.b64decode(encrypted_package["encrypted_key"])
        iv = base64.b64decode(encrypted_package["iv"])

        # Decifra la chiave di sessione con RSA-OAEP
        session_key = recipient_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decifra i dati con AES-CTR
        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return decrypted_data
