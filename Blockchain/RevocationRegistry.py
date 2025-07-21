import hashlib
import json
from datetime import datetime

from Blockchain.Blockchain import Blockchain


class RevocationRegistry:
    """Classe che simula lo Smart Contract per la revoca delle credenziali"""
    def __init__(self, blockchain: 'Blockchain'):
        self.blockchain = blockchain

    def revoke_credential(self, credential_id: str) -> bool:
        """
        Revoca la credenziale corrispondente all'id passato
        :param credential_id: l'id della credenziale da revocare
        :return: true se la revoca è andata a buon fine, altrimenti false
        """
        #Controlla se è già revocata
        if self.is_revoked(credential_id):
            print(f"⚠️ Credenziale {credential_id} già revocata (verificato tramite blockchain simulata).")
            return False

        #Crea il record di revoca
        revocation_record = {
            "credential_id": credential_id,
            "timestamp": datetime.now().isoformat()
        }

        #Crea la transazione di revoca
        transaction = {
            "type": "CREDENTIAL_REVOCATION",
            "credential_id": credential_id,
            "record_hash": hashlib.sha256(json.dumps(revocation_record, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }

        #Aggiunge la transazione alla blockchain
        self.blockchain.add_transaction(transaction)
        print(f"✅ Credenziale {credential_id} revocata e aggiunta alle transazioni pending della blockchain simulata.")
        return True

    def is_revoked(self, credential_id: str) -> bool:
        """
        Verifica se una credenziale è stata revocata cercando nella blockchain.
        :param credential_id: l'id della credenziale da controllare
        :return: true se la credenziale è già revocata, altrimenti false
        '"""
        #Ottiene le transazioni tramite il tipo
        revocation_transactions = self.blockchain.get_transactions_by_type("CREDENTIAL_REVOCATION")

        #Itera tra le transazioni e ottiene la transazione corrispondente all'id passato
        for tx in revocation_transactions:
            if tx.get("credential_id") == credential_id:
                return True #Ritorna True se la trova
        return False