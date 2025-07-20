import json
import uuid
from datetime import datetime
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry
from OtherTechnologiesPepi.HybridCrypto import HybridCrypto


class Actor:
    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        self.private_key = self.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.did = self.generate_did()
        self.did_document = self.generate_did_document()
        self.hybrid_crypto = HybridCrypto()
        self.did_registry = did_registry
        self.revocation_registry = revocation_registry

    @staticmethod
    def generate_private_key():
        """Genera una nuova chiave privata RSA 2048-bit in memoria."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.public_key

    def get_private_key_pem(self) -> bytes:
        """Restituisce la chiave privata in formato PEM (bytes)."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_pem(self) -> bytes:
        """Restituisce la chiave pubblica in formato PEM (bytes)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def generate_did():
        return f"did:{uuid.uuid4()}"


    def generate_did_document(self) -> Dict:
        pem_lines = self.get_public_key_pem().decode('utf-8').splitlines()
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": self.did,
            "verificationMethod": [{
                "id": f"{self.did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": self.did,
                "publicKeyPem": pem_lines,
            }],
            "authentication": [f"{self.did}#key-1"],
            "assertionMethod": [f"{self.did}#key-1"],
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
        }

    def get_did(self) -> str:
        return self.did

    def get_did_document(self) -> Dict:
        return self.did_document

    def sign(self, message: bytes) -> bytes:
        """Firma un messaggio raw in bytes."""
        return self.private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    def sign_structured(self, data: dict) -> bytes:
        """
        Firma un dato strutturato (dict) serializzandolo in JSON e poi firmando i bytes.
        Restituisce la firma in bytes raw.
        """
        # Serializza in JSON con ordinamento chiavi per coerenza
        json_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        # Firma i bytes JSON
        signature = self.sign(json_bytes)
        return signature

    @staticmethod
    def verify(message: bytes, signature: bytes, signer_public_key: rsa.RSAPublicKey) -> bool:
        """Verifica una firma su un messaggio raw in bytes."""
        try:
            signer_public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

    @staticmethod
    def verify_structured(data: dict, signature: bytes, signer_public_key: rsa.RSAPublicKey) -> bool:
        """
        Verifica la firma su dati strutturati serializzati in JSON.
        """
        json_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        return Actor.verify(json_bytes, signature, signer_public_key)