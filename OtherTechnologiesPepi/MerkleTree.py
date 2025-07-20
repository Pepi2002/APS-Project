import hashlib
import json
from typing import Dict, Any, List, Tuple, Optional


class MerkleTree:
    def __init__(self, data: Dict[str, Any]):
        """
        Inizializza l'albero Merkle costruendo le foglie e l'intero albero.
        :param data: dizionario dei dati da usare per generare le foglie
        """
        self.original_data = data
        self.leaves = self.build_leaves(data)
        self.tree = self.build_tree(self.leaves)
        self.merkle_root = self.calculate_merkle_root()

    def get_merkle_root(self):
        return self.merkle_root

    @staticmethod
    def hash_data(data: Any) -> str:
        """
        Hasha un singolo dato serializzato JSON.
        """
        serialized = json.dumps(data, separators=(',', ':'), sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

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

    def build_leaves(self, data: Dict[str, Any]) -> List[str]:
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
    def build_tree(leaves: List[str]) -> List[List[str]]:
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
                combined = bytes.fromhex(left) + bytes.fromhex(right)
                parent_hash = hashlib.sha256(combined).hexdigest()
                next_level.append(parent_hash)
            tree.append(next_level)
            current_level = next_level
        return tree

    def calculate_merkle_root(self) -> str:
        if not self.tree:
            return ''
        return self.tree[-1][0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
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
    def verify_proof(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
        """
        Verifica la Merkle Proof data la foglia, la proof e la root attesa.
        """
        computed_hash = leaf_hash
        for sibling_hash, direction in proof:
            if direction == "left":
                combined = bytes.fromhex(sibling_hash) + bytes.fromhex(computed_hash)
            else:
                combined = bytes.fromhex(computed_hash) + bytes.fromhex(sibling_hash)
            computed_hash = hashlib.sha256(combined).hexdigest()
        return computed_hash == root

    def calculate_merkle_proof(self, attribute_key: str) -> Optional[Dict[str, Any]]:
        flat_items = self.flatten_data(self.original_data)
        index = None
        for i, (path, value) in enumerate(flat_items):
            if path == attribute_key:
                index = i
                leaf_value = value
                break
        if index is None:
            print(f"❌ Chiave {attribute_key} non trovata tra le foglie.")
            return None

        print(f"🔍 Calcolo Merkle Proof per: {attribute_key}")
        leaf_data = {"path": attribute_key, "value": leaf_value}
        leaf_hash = self.hash_data(leaf_data)
        proof_path = self.get_proof(index)
        proof = {
            "attribute": attribute_key,
            "value": leaf_value,
            "leaf_hash": leaf_hash,
            "proof_path": proof_path,
            "root": self.merkle_root  # già stringa esadecimale
        }
        print(f"✅ Merkle Proof generata per {attribute_key}")
        return proof

    def verify_merkle_proof(self, proof: Dict[str, Any]) -> bool:
        print(f"🔍 Verifica Merkle Proof per: {proof['attribute']}")
        leaf_data = {"path": proof['attribute'], "value": proof['value']}
        calculated_hash = self.hash_data(leaf_data)

        if calculated_hash != proof['leaf_hash']:
            print("❌ Hash della foglia non corrisponde")
            return False

        if not self.verify_proof(proof['leaf_hash'], proof['proof_path'], proof['root']):
            print("❌ Merkle Proof non valida")
            return False

        print("✅ Merkle Proof verificata con successo")
        return True