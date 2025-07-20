import hashlib
import json
from datetime import datetime

from BlockchainRaff.Blockchain import Blockchain


class RevocationRegistry:
    def __init__(self, blockchain: 'Blockchain'):
        self.blockchain = blockchain

    def revoke_credential(self, credential_id: str) -> bool:
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