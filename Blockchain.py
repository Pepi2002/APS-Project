import time
from typing import List, Dict

from Block import Block


class Blockchain:
    """Blockchain principale che gestisce DID Registry e Revocation Registry"""

    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.mining_reward = 10
        self.difficulty = 4

        # Crea il blocco genesis
        self.create_genesis_block()

    def create_genesis_block(self):
        """Crea il primo blocco della blockchain"""
        genesis_block = Block(0, [], "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        """Restituisce l'ultimo blocco della chain"""
        return self.chain[-1]

    def add_transaction(self, transaction: Dict):
        """Aggiunge una transazione al pool delle transazioni pending"""
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, mining_reward_address: str = "system"):
        """Mina un nuovo blocco con le transazioni pending"""
        # Aggiungi transazione di reward per il mining
        reward_transaction = {
            "type": "mining_reward",
            "to": mining_reward_address,
            "amount": self.mining_reward,
            "timestamp": time.time()
        }
        self.pending_transactions.append(reward_transaction)

        # Crea nuovo blocco
        block = Block(
            len(self.chain),
            self.pending_transactions,
            self.get_latest_block().hash
        )

        # Mina il blocco
        block.mine_block(self.difficulty)

        # Aggiungi alla chain e resetta pending transactions
        self.chain.append(block)
        self.pending_transactions = []

        print(f"Nuovo blocco aggiunto alla blockchain: {block.index}")

    def is_chain_valid(self) -> bool:
        """Verifica l'integrità della blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Verifica hash del blocco corrente
            if current_block.hash != current_block.calculate_hash():
                print(f"Hash invalido nel blocco {i}")
                return False

            # Verifica collegamento con blocco precedente
            if current_block.previous_hash != previous_block.hash:
                print(f"Blocco {i} non collegato correttamente al precedente")
                return False

        return True

    def get_transactions_by_type(self, transaction_type: str) -> List[Dict]:
        """Filtra le transazioni per tipo"""
        transactions = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("type") == transaction_type:
                    transactions.append(tx)
        return transactions