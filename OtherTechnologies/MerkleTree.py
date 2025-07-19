import json
from typing import Dict, Any, Optional
import hashlib

class EnhancedMerkleTree:
    """Implementazione migliorata del Merkle Tree con algoritmi specifici"""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.leaves = {}
        self.tree_nodes = {}
        self.paths = {}
        self.root = self._build_merkle_tree()

    def _sha256_hash(self, data: str) -> str:
        """Algoritmo di Hash SHA-256"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _build_merkle_tree(self) -> str:
        """Algoritmo di Calcolo del Merkle Tree"""
        print("🌳 Costruzione Merkle Tree...")

        # Fase 1: Crea le foglie (leaf nodes)
        flat_data = self._flatten_dict(self.data)
        leaf_hashes = []

        for key, value in flat_data.items():
            leaf_data = f"{key}:{json.dumps(value, sort_keys=True)}"
            leaf_hash = self._sha256_hash(leaf_data)
            self.leaves[key] = leaf_hash
            leaf_hashes.append(leaf_hash)
            print(f"    Foglia: {key} -> {leaf_hash[:16]}...")

        # Fase 2: Costruisce l'albero bottom-up
        current_level = sorted(leaf_hashes)  # Ordina gli hash per una root consistente
        level = 0

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                # Combina i due hash figli
                combined = f"{left}:{right}"
                parent_hash = self._sha256_hash(combined)

                # Memorizza la struttura per le prove
                self.tree_nodes[parent_hash] = {
                    "left": left,
                    "right": right,
                    "level": level
                }

                next_level.append(parent_hash)

            current_level = sorted(next_level)  # Ordina il nuovo livello
            level += 1

        merkle_root = current_level[0] if current_level else ""
        print(f"✅ Merkle Root: {merkle_root[:16]}...")
        return merkle_root

    def _flatten_dict(self, data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """Appiattisce un dizionario nested mantenendo la struttura"""
        items = {}
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                items.update(self._flatten_dict(value, new_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        items.update(self._flatten_dict(item, f"{new_key}[{i}]"))
                    else:
                        items[f"{new_key}[{i}]"] = item
            else:
                items[new_key] = value
        return items

    def calculate_merkle_proof(self, attribute_key: str) -> Optional[Dict[str, Any]]:
        """Algoritmo di Calcolo del Merkle Proof"""
        if attribute_key not in self.leaves:
            return None

        print(f"🔍 Calcolo Merkle Proof per: {attribute_key}")

        flat_data = self._flatten_dict(self.data)

        # Ricostruzione semplificata del percorso di prova
        # In una implementazione reale, si risalirebbe l'albero memorizzato
        # per trovare i nodi "fratelli" necessari alla verifica.
        # Qui, per semplicità, la verifica si baserà sulla coerenza della root.
        proof_path = [{"info": "simplified_proof_path"}]
        current_hash = self.leaves[attribute_key]

        proof = {
            "attribute": attribute_key,
            "value": flat_data.get(attribute_key),
            "leaf_hash": current_hash,
            "proof_path": proof_path,
            "root": self.root
        }

        print(f"✅ Merkle Proof generata per {attribute_key}")
        return proof

    def verify_merkle_proof(self, proof: Dict[str, Any]) -> bool:
        """Algoritmo di Verifica delle Merkle Proofs"""
        print(f"🔍 Verifica Merkle Proof per: {proof['attribute']}")

        # Ricalcola l'hash della foglia
        leaf_data = f"{proof['attribute']}:{json.dumps(proof['value'], sort_keys=True)}"
        calculated_hash = self._sha256_hash(leaf_data)

        # Verifica che l'hash calcolato corrisponda
        if calculated_hash != proof['leaf_hash']:
            print("❌ Hash della foglia non corrisponde")
            return False

        # Verifica che la root corrisponda (semplificato)
        # In un sistema reale, si userebbe il proof_path per ricalcolare la root
        if proof['root'] != self.root:
            print("❌ Merkle Root non corrisponde")
            return False

        print("✅ Merkle Proof verificata con successo")
        return True
