import hashlib
import json
import uuid
from datetime import datetime

from cryptography.hazmat.primitives import serialization


class DIDRegistry:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.did_documents = {}

    def create_did(self, public_key_pem):
        did = f"did:{uuid.uuid4()}"
        pem_lines = public_key_pem.decode('utf-8').splitlines()
        did_document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": f"{did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyPem": pem_lines,
            }],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
        }

        self.did_documents[did] = did_document

        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document_hash": hashlib.sha256(json.dumps(did_document, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }
        self.blockchain.add_transaction(transaction)

        print(f"✅ DID creato e registrato sulla blockchain simulata: {did}")
        return did

    def get_did_document(self, did: str):
        """Recupera il documento DID associato."""
        return self.did_documents.get(did)

    def get_public_key(self, did: str) -> bytes:
        """Recupera la chiave pubblica PEM in bytes associata a un DID."""
        did_document = self.get_did_document(did)
        if not did_document:
            raise ValueError(f"DID {did} non trovato")

        public_key_pem = did_document["verificationMethod"][0]["publicKeyPem"]
        if isinstance(public_key_pem, list):
            pub_key_str = "\n".join(public_key_pem)
        else:
            pub_key_str = public_key_pem

        return pub_key_str.encode('utf-8')

