import hashlib
import json
import uuid
from datetime import datetime
from typing import Dict

from BlockchainRaff.Blockchain import Blockchain

class DIDRegistry:
    def __init__(self, blockchain: 'Blockchain'):
        self.blockchain = blockchain

    def save_accredited_did(self, did: str, did_document: Dict, certificate: str):
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document": did_document,
            "certificate": certificate,
            "document_hash": hashlib.sha256(json.dumps(did_document, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }
        self.blockchain.add_transaction(transaction)

        print(f"✅ DID creato e aggiunto alle transazioni pending: {did}")
        return did

    def save_did(self, did: str, did_document: Dict):
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document": did_document,
            "document_hash": hashlib.sha256(json.dumps(did_document, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }
        self.blockchain.add_transaction(transaction)

        print(f"✅ DID creato e aggiunto alle transazioni pending: {did}")
        return did

    def get_did_document(self, did: str) -> Dict | None:
        """Recupera il documento DID associato cercando nella blockchain."""
        did_registrations = self.blockchain.get_transactions_by_type("DID_REGISTRATION")

        for tx in reversed(did_registrations):
            if tx.get("did") == did:
                return tx.get("document")
        return None


    def get_public_key(self, did: str) -> bytes:
        """Recupera la chiave pubblica PEM in bytes associata a un DID dalla blockchain."""
        did_document = self.get_did_document(did)
        if not did_document:
            raise ValueError(f"DID {did} non trovato sulla blockchain")

        public_key_pem = did_document["verificationMethod"][0]["publicKeyPem"]
        if isinstance(public_key_pem, list):
            pub_key_str = "\n".join(public_key_pem)
        else:
            pub_key_str = public_key_pem

        return pub_key_str.encode('utf-8')