import time
from typing import List, Dict

from Block import Block


class Blockchain:
    """Classe che simula la blockchain che fornisce il did registry e il revocation registry"""

    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        self.mining_reward = 10
        self.difficulty = 4

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
        #Crea una transazione
        reward_transaction = {
            "type": "mining_reward",
            "to": mining_reward_address,
            "amount": self.mining_reward,
            "timestamp": time.time()
        }

        #Aggiunge alle transazioni pendenti
        self.pending_transactions.append(reward_transaction)

        #Crea un nuovo blocco
        block = Block(
            len(self.chain),
            self.pending_transactions,
            self.get_latest_block().hash
        )

        #Esegue il mining
        block.mine_block(self.difficulty)

        #Aggiunge il blocco minato alla blockchain
        self.chain.append(block)
        self.pending_transactions = []

        print(f"Nuovo blocco aggiunto alla blockchain: {block.index}")

    def is_chain_valid(self) -> bool:
        """Verifica l'integrità della blockchain"""
        #Cicla sui blocchi della catena
        for i in range(1, len(self.chain)):
            #Prende blocco corrente e quello precedente
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            #Ricalcola l'hash e lo confronta con quello memorizzato
            if current_block.hash != current_block.calculate_hash():
                print(f"Hash invalido nel blocco {i}")
                return False

            #Controlla che il campo previous hash corrisponde all'hash del blocco precedente
            if current_block.previous_hash != previous_block.hash:
                print(f"Blocco {i} non collegato correttamente al precedente")
                return False
        return True

    def get_transactions_by_type(self, transaction_type: str) -> List[Dict]:
        """Filtra le transazioni per tipo"""
        transactions = []

        #Scorre ogni blocco nella chain
        for block in self.chain:
            #Scorre le transazioni in ogni blocco
            for tx in block.transactions:
                #Controlla che il campo type è uguale a quello richiesto
                #Se è uguale aggiunge la transazione alla lista da restituire
                if tx.get("type") == transaction_type:
                    transactions.append(tx)
        return transactions