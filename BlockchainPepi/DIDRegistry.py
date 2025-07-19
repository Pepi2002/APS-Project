import hashlib
import json
import uuid
from datetime import datetime
from typing import List, Dict # Import per i tipi di dato

# Assicurati che queste classi siano importate o definite sopra
from Block import Block
from Blockchain import Blockchain

class DIDRegistry:
    def __init__(self, blockchain: 'Blockchain'): # Specifichiamo il tipo di blockchain
        self.blockchain = blockchain
        # Non è più necessario self.did_documents in memoria,
        # lo stato dei DID sarà letto dalla blockchain

    def create_did(self, public_key_pem: bytes) -> str:
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

        # La transazione contiene il DID Document completo
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document": did_document, # Invece dell'hash, mettiamo il documento completo
            "document_hash": hashlib.sha256(json.dumps(did_document, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }
        self.blockchain.add_transaction(transaction)

        print(f"✅ DID creato e aggiunto alle transazioni pending: {did}")
        return did

    def get_did_document(self, did: str) -> Dict | None:
        """Recupera il documento DID associato cercando nella blockchain."""
        # Filtra tutte le transazioni di registrazione DID
        did_registrations = self.blockchain.get_transactions_by_type("DID_REGISTRATION")

        # Cerca il DID più recente per l'ID specificato
        # In un sistema reale con aggiornamenti, cercheresti l'ultima transazione valida per quel DID
        # Per questa simulazione, cerchiamo il primo che corrisponde
        for tx in reversed(did_registrations): # Ricerca all'indietro per il più recente se ci fossero aggiornamenti
            if tx.get("did") == did:
                return tx.get("document") # Restituisce il documento completo dalla transazione
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