import hashlib
import json
from datetime import datetime
from typing import Dict

from Blockchain.Blockchain import Blockchain

class DIDRegistry:
    """Simula lo Smart Contract per il salvtaggio dei did sulla blockchain"""

    def __init__(self, blockchain: 'Blockchain'):
        self.blockchain = blockchain

    def save_accredited_did(self, did: str, did_document: Dict, certificate: str):
        """
        Salva il did accreditato con certificato nella blockchain
        :param did: il did da salvare
        :param did_document: il did document corrispondente
        :param certificate: il certificato corrispondente
        :return: il did che è stato salvato
        """
        #Crea la transazione
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document": did_document,
            "certificate": certificate,
            "document_hash": hashlib.sha256(json.dumps(did_document, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }

        #Aggiunge la transazione alla blockchain
        self.blockchain.add_transaction(transaction)

        print(f"✅ DID creato e aggiunto alle transazioni pending: {did}")
        return did

    def save_did(self, did: str, did_document: Dict):
        """
        Salva il did non accreditato e senza certificato
        :param did: il did da salvare
        :param did_document: il documento corrispondente
        :return: il did che è stato salvato
        """
        #Crea la transazione
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document": did_document,
            "document_hash": hashlib.sha256(json.dumps(did_document, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }

        #Aggiunge la transazione alla blockchain
        self.blockchain.add_transaction(transaction)

        print(f"✅ DID creato e aggiunto alle transazioni pending: {did}")
        return did

    def get_did_document(self, did: str) -> Dict | None:
        """
        Recupera il documento DID associato cercando nella blockchain.
        :param did: il did corrispondente al documento da ottenere
        :return: il documento DID corrispondente
        """
        #Ottiene la transazione attraverso il tipo
        did_registrations = self.blockchain.get_transactions_by_type("DID_REGISTRATION")

        #Itera tra le transizione e ottiene quella corrispondente al did passato
        for tx in reversed(did_registrations):
            if tx.get("did") == did:
                return tx.get("document") #Ritorna il documento
        return None


    def get_public_key(self, did: str) -> bytes:
        """
        Recupera la chiave pubblica PEM in bytes associata a un DID dalla blockchain.
        :param did: il did corrispondente alla chiave pubblica da ottenere
        :return: la chiave pubblica corrispondente
        """
        #Ottiene il documento attraverso il did
        did_document = self.get_did_document(did)

        #Controlla che esisti un documento corrispondente al did
        if not did_document:
            raise ValueError(f"DID {did} non trovato sulla blockchain")

        #Ottiene la chiave pubblica presente nel documento
        public_key_pem = did_document["verificationMethod"][0]["publicKeyPem"]
        if isinstance(public_key_pem, list):
            pub_key_str = "\n".join(public_key_pem)
        else:
            pub_key_str = public_key_pem

        return pub_key_str.encode('utf-8')

    def get_certificate(self, did: str) -> str | None:
        """
        Recupera il certificato JWT di accreditamento associato a un DID, se presente.
        :param did: il did corrsipondente al certificato da ottenere
        :return: il certificato JWT corrispondente
        """
        #Ottiene le transazioni tramite il tipo
        did_registrations = self.blockchain.get_transactions_by_type("DID_REGISTRATION")

        #Itera tra le transizione e ottiene quella corrispondente al did passato
        for tx in reversed(did_registrations):
            if tx.get("did") == did:
                return tx.get("certificate") #Ritorna il certificato

        return None