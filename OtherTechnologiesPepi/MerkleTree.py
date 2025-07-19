import hashlib
import json
from typing import Dict, Any, List, Tuple


class MerkleTree:
    def __init__(self, data: Dict[str, Any]):
        """
        Inizializza l'albero Merkle costruendo le foglie e l'intero albero.
        :param data: dizionario dei dati da usare per generare le foglie
        """
        self.leaves = self.build_leaves(data)
        self.tree = self.build_tree(self.leaves)
        self.merkle_root = self.calculate_merkle_root()

    def get_merkle_root(self):
        return self.merkle_root

    @staticmethod
    def hash_data(data: Any) -> bytes:
        """
        Hasha un singolo dato serializzato JSON.
        """
        serialized = json.dumps(data, separators=(',', ':'), sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).digest()

    def flatten_data(self, data: Any, path: str = '') -> List[Tuple[str, Any]]:
        """
        Appiattisce ricorsivamente i dati in una lista di (chiave_path, valore_atomico).
        """
        items = []
        if isinstance(data, dict):
            for k, v in data.items():
                new_path = f"{path}.{k}" if path else k
                items.extend(self.flatten_data(v, new_path))
        elif isinstance(data, list):
            for i, v in enumerate(data):
                new_path = f"{path}[{i}]"
                items.extend(self.flatten_data(v, new_path))
        else:
            items.append((path, data))
        return items

    def build_leaves(self, data: Dict[str, Any]) -> List[bytes]:
        """
        Costruisce la lista delle foglie hashate dal dizionario dati.
        """
        flat_items = self.flatten_data(data)
        leaves = []
        for path, value in flat_items:
            # qui puoi anche includere la path per un hashing più robusto, es:
            leaf_data = {"path": path, "value": value}
            leaves.append(self.hash_data(leaf_data))
        return leaves

    @staticmethod
    def build_tree(leaves: List[bytes]) -> List[List[bytes]]:
        """
        Costruisce i livelli dell'albero Merkle fino alla root.
        """
        tree = [leaves]
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i + 1 < len(current_level) else current_level[i]
                combined = left + right
                parent_hash = hashlib.sha256(combined).digest()
                next_level.append(parent_hash)
            tree.append(next_level)
            current_level = next_level
        return tree

    def calculate_merkle_root(self) -> str:
        if not self.tree:
            return ''
        return self.tree[-1][0].hex()

    def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
        """
        Restituisce la Merkle Proof per la foglia all'indice dato.
        Ogni elemento è una tupla (hash_fratello, "left" o "right").
        """
        proof = []
        idx = index
        for level in self.tree[:-1]:
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
                direction = "right" if idx % 2 == 0 else "left"
                proof.append((sibling_hash, direction))
            idx = idx // 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: List[Tuple[bytes, str]], root: bytes) -> bool:
        """
        Verifica la Merkle Proof data la foglia, la proof e la root attesa.
        """
        computed_hash = leaf_hash
        for sibling_hash, direction in proof:
            if direction == "left":
                combined = sibling_hash + computed_hash
            else:
                combined = computed_hash + sibling_hash
            computed_hash = hashlib.sha256(combined).digest()
        return computed_hash == root