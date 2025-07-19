import hashlib
import json
from datetime import datetime

# Assicurati che queste classi siano importate o definite sopra
from BlockchainRaff.Blockchain import Blockchain


class RevocationRegistry:
    def __init__(self, blockchain: 'Blockchain'): # Specifichiamo il tipo di blockchain
        self.blockchain = blockchain
        # Non è più necessario self.revoked_credentials in memoria,
        # lo stato delle revoche sarà letto dalla blockchain al bisogno.
        # Oppure, per performance, potresti ricaricarlo all'avvio da blockchain.

    def revoke_credential(self, credential_id: str) -> bool:
        # In una vera blockchain, non puoi verificare se è già revocata prima di inviare la transazione
        # È il contratto intelligente che gestisce lo stato on-chain.
        # Per la simulazione, possiamo fare una verifica prima di aggiungere la transazione.
        if self.is_revoked(credential_id):
            print(f"⚠️ Credenziale {credential_id} già revocata (verificato tramite blockchain simulata).")
            return False

        revocation_record = {
            "credential_id": credential_id,
            "timestamp": datetime.now().isoformat()
        }

        transaction = {
            "type": "CREDENTIAL_REVOCATION",
            "credential_id": credential_id,
            "record_hash": hashlib.sha256(json.dumps(revocation_record, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }

        self.blockchain.add_transaction(transaction)
        print(f"✅ Credenziale {credential_id} revocata e aggiunta alle transazioni pending della blockchain simulata.")
        return True

    def is_revoked(self, credential_id: str) -> bool:
        """Verifica se una credenziale è stata revocata cercando nella blockchain."""
        revocation_transactions = self.blockchain.get_transactions_by_type("CREDENTIAL_REVOCATION")
        for tx in revocation_transactions:
            if tx.get("credential_id") == credential_id:
                return True
        return False