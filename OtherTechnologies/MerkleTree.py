import hashlib
import json
from typing import Dict, Any, List, Tuple, Optional


class MerkleTree:
    """Classe utilizzata per la creazione e l'utilizzo del merkle tree"""

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
        """
        Metodo per ottenere la merkle root dell'albero
        :return: la merkle root
        """
        return self.merkle_root

    @staticmethod
    def hash_data(data: Any) -> str:
        """
        Hasha un singolo dato serializzato JSON.
        :param data: dato da hashare
        """
        serialized = json.dumps(data, separators=(',', ':'), sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    @staticmethod
    def flatten_data(data: Any, path: str = '') -> List[Tuple[str, Any]]:
        """
        Appiattisce ricorsivamente i dati in una lista di (chiave_path, valore_atomico).
        :param data: dato da hashare
        :param path: path del dato
        :return: una lista di (chiave_path, valore_atomico)
        """
        items = []
        #Caso in cui data è un dizionario
        if isinstance(data, dict):
            for k, v in data.items():
                new_path = f"{path}.{k}" if path else k
                items.extend(MerkleTree.flatten_data(v, new_path)) #Ricorsione
        elif isinstance(data, list): #Caso in cui data è una lista
            for i, v in enumerate(data):
                new_path = f"{path}[{i}]"
                items.extend(MerkleTree.flatten_data(v, new_path)) #Ricorsione
        else: #Caso in cui è un valore atomico
            items.append((path, data))
        return items

    def build_leaves(self, data: Dict[str, Any]) -> List[str]:
        """
        Costruisce la lista delle foglie hashate dal dizionario dati.
        :param data: dato da hashare
        :return: lista della foglie hashata
        """
        #Appiattisce i dati
        flat_items = self.flatten_data(data)
        leaves = []

        #Itera sui dati appiattiti attraverso coppie (path, valore)
        for path, value in flat_items:
            leaf_data = {"path": path, "value": value}

            #Esegue l'hash del dato e lo aggiunge alla lista di foglie
            leaves.append(self.hash_data(leaf_data))
        return leaves

    @staticmethod
    def build_tree(leaves: List[str]) -> List[List[str]]:
        """
        Costruisce i livelli dell'albero Merkle fino alla root.
        :param leaves: l'insieme di foglie con cui creare il merkle tree
        """
        #Primo livello dell'albero
        tree = [leaves]

        #Livello da cui partire
        current_level = leaves

        #Si itera sui livelli fino ad arrivare alla merkle root
        while len(current_level) > 1:
            next_level = [] #Nuovo livello

            #Itera a coppie di nodi
            for i in range(0, len(current_level), 2):
                left = current_level[i] #Nodo sinistro
                right = current_level[i+1] if i + 1 < len(current_level) else current_level[i] # nodo destro

                #Combina i due hash (convertiti da esadecimale a bytes)
                combined = bytes.fromhex(left) + bytes.fromhex(right)

                #Ottieni l'hash del nodo padre
                parent_hash = hashlib.sha256(combined).hexdigest()

                #Aggiungi nodo padre al nuovo livello
                next_level.append(parent_hash)

            #Aggiungi il nuovo livello all'albero
            tree.append(next_level)

            #Aumenta il livello corrente
            current_level = next_level
        return tree

    def calculate_merkle_root(self) -> str:
        """
        Metodo per calcolare la merkle root di un merkle tree
        :return: la merkle root
        """
        if not self.tree:
            return ''
        return self.tree[-1][0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Restituisce la Merkle Proof per la foglia all'indice dato.
        Ogni elemento è una tupla (hash_fratello, "left" o "right").
        :param index: indice di foglia
        :return: lista della foglia hashata
        """
        # Lista che conterrà la merkle proof
        proof = []
        idx = index

        #itera su ogni livello tranne nella merkle root
        for level in self.tree[:-1]:

            #Calcoliamo l'indice del fratello
            #(Se è pari è quello destro, se è dispari è quello sinistro)
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1

            #Controllo se il fratello esiste in quel livello
            if sibling_idx < len(level):
                #Hash del fratello
                sibling_hash = level[sibling_idx]

                #Posizione del fratello rispetto al nodo
                direction = "right" if idx % 2 == 0 else "left"

                #Aggiunta della proof
                proof.append((sibling_hash, direction))

            #Passo al livello successivo
            idx = idx // 2
        return proof

    def calculate_merkle_proof(self, attribute_key: str) -> Optional[Tuple[Any, List[Tuple[str, str]]]]:
        """
        Metodo per calcolare i merkle proof a partire di un insieme di attributi
        :param attribute_key: il percorso dell'attributo per cui ottenere la Merkle proof (es. "studentInfo.name")
        :return: una tupla contenente il valore della foglia e la lista della Merkle proof, oppure None se non trovato
        """
        #Appiattisce i dati originali
        flat_items = self.flatten_data(self.original_data)

        #Cerca la posizione dell'attributo (attribute key)
        leaf_value = None
        index = None
        for i, (path, value) in enumerate(flat_items):
            if path == attribute_key:
                index = i
                leaf_value = value
                break

        #Se non trova l'attributo mostra un messaggio di errore
        if index is None:
            print(f"❌ Chiave {attribute_key} non trovata tra le foglie.")
            return None

        print(f"Calcolo Merkle Proof per: {attribute_key}...")

        #Recupera la proof per la foglia all'indice trovato
        proof_path = self.get_proof(index)
        print(f"✅ Merkle Proof generata per {attribute_key}")
        return leaf_value, proof_path

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
        """
        Verifica la Merkle Proof data la foglia, la proof e la root attesa.
        :param leaf_hash: hash della foglia
        :param proof: prrof corrispondente alla foglia
        :param root: la merkle root con cui verificare la proof
        :return true se la verifica è andata a buon fine, altrimenti false
        """
        # Hash della foglia di partenza
        computed_hash = leaf_hash

        # Itera sulle proof tramite l'hash del fratello e la sua direzione
        for sibling_hash, direction in proof:
            # Combina gli hash a seconda della direzione
            if direction == "left":
                combined = bytes.fromhex(sibling_hash) + bytes.fromhex(computed_hash)
            else:
                combined = bytes.fromhex(computed_hash) + bytes.fromhex(sibling_hash)

            # Calcola l'hash del concatenamento ottenuto, ossia il padre
            computed_hash = hashlib.sha256(combined).hexdigest()

        # Confronta l'hash finale ottenuto con la root
        return computed_hash == root