import hashlib
import json
from datetime import datetime

class EnhancedRevocationRegistry:
    """Registro di revoca migliorato con simulazione blockchain più realistica"""

    def __init__(self):
        self.revoked_credentials = {}
        self.blockchain_blocks = []
        self.current_block = []
        self.difficulty = 4  # Numero di zeri iniziali per il mining
        self.mining_reward = 10
        self.gas_price = 0.001

    def _mine_block(self, transactions):
        """Simula il mining di un blocco con Proof of Work"""
        nonce = 0
        previous_hash = self.blockchain_blocks[-1]["hash"] if self.blockchain_blocks else "0" * 64
        max_nonce = 1000000  # Limite massimo per evitare loop infiniti

        while nonce < max_nonce:
            block_data = {
                "block_number": len(self.blockchain_blocks),
                "timestamp": datetime.now().isoformat(),
                "transactions": transactions,
                "previous_hash": previous_hash,
                "nonce": nonce
            }

            block_hash = hashlib.sha256(
                json.dumps(block_data, sort_keys=True).encode()
            ).hexdigest()

            if block_hash.startswith("0" * self.difficulty):
                block_data["hash"] = block_hash
                return block_data

            nonce += 1

        # Se non trova soluzione, riduce la difficoltà
        self.difficulty = max(1, self.difficulty - 1)
        return self._mine_block(transactions)

    def _create_block(self):
        """Crea un nuovo blocco con mining simulato"""
        if self.current_block:
            print(f"⛏️  Mining blocco #{len(self.blockchain_blocks)}...")
            block = self._mine_block(self.current_block.copy())
            self.blockchain_blocks.append(block)
            self.current_block = []
            print(f"📦 Blocco #{block['block_number']} minato con successo!")
            print(f"🔗 Hash: {block['hash'][:16]}...")

    def simulate_smart_contract_call(self, function_name, params):
        """Simula la chiamata a uno smart contract"""
        gas_used = len(json.dumps(params)) * 10  # Simula il gas usage
        transaction_fee = gas_used * self.gas_price

        return {
            "function": function_name,
            "params": params,
            "gas_used": gas_used,
            "transaction_fee": transaction_fee,
            "block_timestamp": datetime.now().isoformat()
        }

    def is_revoked(self, credential_id: str) -> bool:
        """Verifica se una credenziale è revocata"""
        return credential_id in self.revoked_credentials

    def revoke_credential(self, credential_id: str, issuer_did: str,
                          signature: str, reason: str = "unspecified") -> bool:
        """Revoca con simulazione smart contract"""
        if credential_id not in self.revoked_credentials:
            # Simula chiamata smart contract
            smart_contract_call = self.simulate_smart_contract_call(
                "revokeCredential",
                {
                    "credentialId": credential_id,
                    "issuerDid": issuer_did,
                    "reason": reason
                }
            )

            revocation_record = {
                "credential_id": credential_id,
                "issuer_did": issuer_did,
                "timestamp": datetime.now().isoformat(),
                "signature": signature,
                "reason": reason,
                "smart_contract_call": smart_contract_call,
                "block_height": len(self.blockchain_blocks)
            }

            self.revoked_credentials[credential_id] = revocation_record
            self.current_block.append(revocation_record)

            print(f"📜 Smart contract 'revokeCredential' chiamato")
            print(f"⛽ Gas utilizzato: {smart_contract_call['gas_used']}")
            print(f"💰 Fee: {smart_contract_call['transaction_fee']:.6f} ETH")

            # Crea blocco se necessario
            if len(self.current_block) >= 2:  # Blocco più piccolo per demo
                self._create_block()

            return True
        return False

    def get_blockchain_state(self):
        """Restituisce lo stato della blockchain simulata"""
        return {
            "total_blocks": len(self.blockchain_blocks),
            "pending_transactions": len(self.current_block),
            "total_revocations": len(self.revoked_credentials),
            "last_block_hash": self.blockchain_blocks[-1]["hash"] if self.blockchain_blocks else None
        }
