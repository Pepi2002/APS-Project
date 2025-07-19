import hashlib
import json
from datetime import datetime


class RevocationRegistry:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.revoked_credentials = set()

    def revoke_credential(self, credential_id: str):
        if credential_id in self.revoked_credentials:
            print(f"⚠️ Credenziale {credential_id} già revocata.")
            return False

        revocation_record = {
            "credential_id": credential_id,
            "timestamp": datetime.now().isoformat()
        }

        self.revoked_credentials.add(credential_id)

        transaction = {
            "type": "CREDENTIAL_REVOCATION",
            "credential_id": credential_id,
            "record_hash": hashlib.sha256(json.dumps(revocation_record, sort_keys=True).encode()).hexdigest(),
            "timestamp": datetime.now().isoformat()
        }

        self.blockchain.add_transaction(transaction)
        print(f"✅ Credenziale {credential_id} revocata e registrata sulla blockchain simulata.")
        return True

    def is_revoked(self, credential_id: str) -> bool:
        return credential_id in self.revoked_credentials