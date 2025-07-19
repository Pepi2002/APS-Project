import hashlib
import json
from datetime import datetime


class SimulatedBlockchain:
    def __init__(self, max_transaction_block = 5):
        self.chain = []
        self.current_transactions = []
        self.max_transaction_block = max_transaction_block

    def get_chain(self):
        """Restituisce la catena completa."""
        return self.chain

    def get_last_block(self):
        """Restituisce l'ultimo blocco."""
        return self.chain[-1] if self.chain else None

    def get_current_transactions(self):
        return self.current_transactions

    def is_transaction_in_chain(self, transaction_hash: str) -> bool:
        """Verifica se una transazione è in un blocco della catena (tramite hash)."""
        for block in self.chain:
            for tx in block["transactions"]:
                tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                if tx_hash == transaction_hash:
                    return True
        return False

    @staticmethod
    def hash_block(block):
        """Calcola l'hash SHA256 di un blocco"""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def add_transaction(self, transaction: dict):
        """Aggiunge una nuova transazione al blocco corrente."""
        transaction["timestamp"] = datetime.now().isoformat()
        self.current_transactions.append(transaction)

        # Se abbiamo raggiunto il numero massimo, chiudiamo il blocco
        if len(self.current_transactions) >= self.max_transaction_block:
            self.create_block()

    def create_block(self):
        """Crea un nuovo blocco e lo aggiunge alla catena."""
        previous_hash = self.chain[-1]["hash"] if self.chain else "0" * 64
        block = {
            "index": len(self.chain),
            "timestamp": datetime.now().isoformat(),
            "transactions": self.current_transactions,
            "previous_hash": previous_hash
        }
        block["hash"] = self.hash_block(block)
        self.chain.append(block)
        self.current_transactions = []
        print(f"📦 Blocco #{block['index']} creato con {len(block['transactions'])} transazioni.")
