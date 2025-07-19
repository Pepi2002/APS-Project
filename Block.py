import hashlib
import json
import time
from typing import List, Dict


class Block:
    """Rappresenta un singolo blocco nella blockchain"""

    def __init__(self, index: int, transactions: List[Dict], previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calcola l'hash SHA-256 del blocco"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty: int = 4):
        """Implementa il Proof of Work per il mining del blocco"""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Blocco minato: {self.hash}")