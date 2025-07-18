import hashlib
import json
from datetime import datetime
from NumberGenerator import CSPRNGGenerator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import uuid

class EnhancedDIDManager:
    """Gestore DID con simulazione blockchain"""

    def __init__(self):
        self.did_registry = {}
        self.blockchain_blocks = []
        self.current_block = []
        self.accreditation_authorities = set()
        self.csprng = CSPRNGGenerator()

    def simulate_did_registration_on_blockchain(self, did: str, did_document: dict):
        """Simula la registrazione del DID su blockchain"""
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document_hash": hashlib.sha256(
                json.dumps(did_document, sort_keys=True).encode()
            ).hexdigest(),
            "timestamp": datetime.now().isoformat(),
            "gas_used": 50000,
            "transaction_fee": 0.001
        }

        self.current_block.append(transaction)
        print(f"📋 DID registrato su blockchain simulata")
        print(f"🔗 Transaction hash: {transaction['document_hash'][:16]}...")

        return transaction

    def create_did(self, entity_name: str, entity_type: str,
                   public_key: RSAPublicKey,
                   accreditation_authority: str = None) -> str:
        """Crea DID con registrazione blockchain simulata"""
        did = f"did:erasmus:{entity_type}:{uuid.uuid4()}"

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        did_document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "controller": entity_name,
            "verificationMethod": [{
                "id": f"{did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyPem": public_key_pem
            }],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "entityType": entity_type,
            "accreditation_authority": accreditation_authority
        }

        # Registra su blockchain simulata
        self.simulate_did_registration_on_blockchain(did, did_document)

        self.did_registry[did] = did_document
        print(f"✅ DID creato: {did}")
        return did

    def get_public_key(self, did: str) -> RSAPublicKey:
        """Recupera la chiave pubblica associata a un DID"""
        if did not in self.did_registry:
            raise ValueError(f"DID {did} non trovato nel registro")

        did_document = self.did_registry[did]
        public_key_pem = did_document["verificationMethod"][0]["publicKeyPem"]

        # Converti da PEM a oggetto RSAPublicKey
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        return public_key
