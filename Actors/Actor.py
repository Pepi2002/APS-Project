import uuid
from datetime import datetime
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from OtherTechnologies.HybridCrypto import HybridCrypto


class Actor:
    """Classe che simula Attore generico"""

    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        self.private_key = self.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.did = f"did:{uuid.uuid4()}"
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


    def generate_did_document(self) -> Dict:
        """
        Genera un did document
        :return: did document generato
        """
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
        }

    def get_did(self) -> str:
        """
        Metodo per ottenere il did di un attore
        :return: did di un attore
        """
        return self.did

    def get_did_document(self) -> Dict:
        """
        Metodo per ottenere il did document di un attore
        :return: il did document di un attore
        """
        return self.did_document