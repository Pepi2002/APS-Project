import json
import hashlib
import jwt
import time
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Dict, List, Any, Optional, Tuple
import secrets
import base64
import os


class CSPRNGGenerator:
    """Generatore di Numeri Pseudo Casuali Crittograficamente Sicuro"""

    @staticmethod
    def generate_key_material(length: int) -> bytes:
        """Genera materiale crittografico sicuro"""
        return secrets.token_bytes(length)

    @staticmethod
    def generate_nonce() -> str:
        """Genera un nonce unico per prevenire replay attacks"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_session_key() -> bytes:
        """Genera una chiave di sessione AES-256"""
        return secrets.token_bytes(32)  # 256 bits


class HybridCrypto:
    """Implementazione della crittografia ibrida RSA-OAEP + AES-CTR"""

    def __init__(self):
        self.csprng = CSPRNGGenerator()

    def encrypt_hybrid(self, data: bytes, recipient_public_key: RSAPublicKey) -> Dict[str, str]:
        """Cifratura ibrida: AES-CTR per i dati + RSA-OAEP per la chiave"""
        # Genera chiave simmetrica temporanea
        session_key = self.csprng.generate_session_key()

        # Genera IV casuale per AES-CTR
        iv = os.urandom(16)

        # Cifra i dati con AES-CTR
        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Cifra la chiave di sessione con RSA-OAEP
        encrypted_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(iv).decode()
        }

    def decrypt_hybrid(self, encrypted_package: Dict[str, str],
                       recipient_private_key: RSAPrivateKey) -> bytes:
        """Decifratura ibrida"""
        # Decodifica i componenti
        encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])
        encrypted_key = base64.b64decode(encrypted_package["encrypted_key"])
        iv = base64.b64decode(encrypted_package["iv"])

        # Decifra la chiave di sessione con RSA-OAEP
        session_key = recipient_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decifra i dati con AES-CTR
        cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return decrypted_data


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


# Aggiungi queste migliorie alla tua classe EnhancedRevocationRegistry

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


# Aggiungi anche una simulazione DID Registry migliorata
class EnhancedDIDManager:
    """Gestore DID con simulazione blockchain"""

    def __init__(self):
        self.did_registry = {}
        self.blockchain_blocks = []
        self.current_block = []
        self.accreditation_authorities = set()
        self.csprng = CSPRNGGenerator()

    def simulate_did_registration_on_blockchain(self, did: str, did_document: dict):
        """Simula la registrazione del DID su blockchain"""
        transaction = {
            "type": "DID_REGISTRATION",
            "did": did,
            "document_hash": hashlib.sha256(
                json.dumps(did_document, sort_keys=True).encode()
            ).hexdigest(),
            "timestamp": datetime.now().isoformat(),
            "gas_used": 50000,
            "transaction_fee": 0.001
        }

        self.current_block.append(transaction)
        print(f"📋 DID registrato su blockchain simulata")
        print(f"🔗 Transaction hash: {transaction['document_hash'][:16]}...")

        return transaction

    def create_did(self, entity_name: str, entity_type: str,
                   public_key: RSAPublicKey,
                   accreditation_authority: str = None) -> str:
        """Crea DID con registrazione blockchain simulata"""
        did = f"did:erasmus:{entity_type}:{uuid.uuid4()}"

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        did_document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "controller": entity_name,
            "verificationMethod": [{
                "id": f"{did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyPem": public_key_pem
            }],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "entityType": entity_type,
            "accreditation_authority": accreditation_authority
        }

        # Registra su blockchain simulata
        self.simulate_did_registration_on_blockchain(did, did_document)

        self.did_registry[did] = did_document
        print(f"✅ DID creato: {did}")
        return did

    def get_public_key(self, did: str) -> RSAPublicKey:
        """Recupera la chiave pubblica associata a un DID"""
        if did not in self.did_registry:
            raise ValueError(f"DID {did} non trovato nel registro")

        did_document = self.did_registry[did]
        public_key_pem = did_document["verificationMethod"][0]["publicKeyPem"]

        # Converti da PEM a oggetto RSAPublicKey
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        return public_key

class EnhancedErasmusCredentialSystem:
    """Sistema migliorato per la gestione delle credenziali Erasmus"""

    def __init__(self):
        self.did_manager = EnhancedDIDManager()
        self.revocation_registry = EnhancedRevocationRegistry()
        self.hybrid_crypto = HybridCrypto()
        self.csprng = CSPRNGGenerator()
        self.used_nonces = set()
        self._generate_asymmetric_keys()

    def _generate_asymmetric_keys(self):
        """Algoritmo di Generazione delle Chiavi Asimmetriche (Gen K)"""
        print("🔑 Generazione chiavi asimmetriche con CSPRNG...")

        # Genera chiavi per l'Università Ospitante
        self.host_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.host_public_key = self.host_private_key.public_key()

        # Genera chiavi per l'Università di Origine
        self.home_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.home_public_key = self.home_private_key.public_key()

        # Genera chiavi per lo Studente
        self.student_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.student_public_key = self.student_private_key.public_key()

        # Crea i DID per le entità
        self.host_did = self.did_manager.create_did(
            "Université de Rennes", "university", self.host_public_key
        )
        self.home_did = self.did_manager.create_did(
            "Università di Salerno", "university", self.home_public_key
        )
        self.student_did = self.did_manager.create_did(
            "Mario Rossi", "student", self.student_public_key
        )

        print("✅ Chiavi asimmetriche generate e DID creati")

    def create_detailed_student_data(self) -> Dict[str, Any]:
        """Crea dati dettagliati dello studente per test"""
        return {
            "studentInfo": {
                "name": "Mario",
                "surname": "Rossi",
                "studentId": "0512345678",
                "birthdate": "1999-03-15",
                "nationality": "Italian",
                "email": "m.rossi@studenti.unisa.it",
                "degreeCourse": "Ingegneria Informatica",
                "academicYear": "2024-2025",
                "homeUniversity": {
                    "name": "Università di Salerno",
                    "code": "UNISA",
                    "country": "Italy",
                    "did": self.home_did
                }
            },
            "erasmusInfo": {
                "hostUniversity": {
                    "name": "Université de Rennes",
                    "code": "UR1",
                    "country": "France",
                    "did": self.host_did
                },
                "erasmusStartDate": "2024-09-01",
                "erasmusEndDate": "2025-01-31",
                "learningAgreement": {
                    "period": "Fall 2024",
                    "courses": [
                        {
                            "courseName": "Advanced Algorithms",
                            "courseCode": "CS501",
                            "ects": 6,
                            "status": "passed",
                            "grade": 28,
                            "gradeScale": "30",
                            "honor": False,
                            "completionDate": "2024-12-15"
                        },
                        {
                            "courseName": "Machine Learning",
                            "courseCode": "CS502",
                            "ects": 6,
                            "status": "passed",
                            "grade": 30,
                            "gradeScale": "30",
                            "honor": True,
                            "completionDate": "2024-12-20"
                        }
                    ],
                    "totalCredits": 12
                },
                "languageCertificates": [
                    {
                        "language": "French",
                        "level": "B2",
                        "certification": "DELF",
                        "score": 85,
                        "date": "2024-08-15"
                    }
                ]
            }
        }

    def issue_verifiable_credential(self, student_data: Dict[str, Any]) -> str:
        """Emissione di Verifiable Credential con Merkle Tree - Stampe migliorate"""
        print("🏛️  EMISSIONE VERIFIABLE CREDENTIAL")
        print("=" * 50)

        # Stampa informazioni studente
        student_info = student_data.get("studentInfo", {})
        print(f"📋 Studente: {student_info.get('name', 'N/A')} {student_info.get('surname', 'N/A')}")
        print(f"🎓 Corso: {student_info.get('degreeCourse', 'N/A')}")
        print(
            f"🏫 Università ospitante: {student_data.get('erasmusInfo', {}).get('hostUniversity', {}).get('name', 'N/A')}")
        print(
            f"📅 Periodo Erasmus: {student_data.get('erasmusInfo', {}).get('erasmusStartDate', 'N/A')} - {student_data.get('erasmusInfo', {}).get('erasmusEndDate', 'N/A')}")
        print()

        # Crea il Merkle Tree dai dati dello studente
        print("🌳 Creazione Merkle Tree per integrità dati...")
        merkle_tree = EnhancedMerkleTree(student_data)
        credential_id = str(uuid.uuid4())
        print(f"🆔 ID Credenziale generato: {credential_id}")
        print(f"🔗 Merkle Root calcolata: {merkle_tree.root[:32]}...")
        print()

        # Genera timestamp
        now = datetime.now()
        expiration_date = now + timedelta(days=365)

        print("📅 Informazioni temporali:")
        print(f"   📋 Data emissione: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   ⏰ Data scadenza: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        # Crea il payload del JWT secondo lo standard W3C VC
        vc_payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://erasmus.eu/2024/credentials/v1"
            ],
            "id": f"https://erasmus.eu/credentials/{credential_id}",
            "type": ["VerifiableCredential", "ErasmusCredential"],
            "issuer": {
                "id": self.host_did,
                "name": "Université de Rennes"
            },
            "credentialSubject": {
                "id": self.student_did,
                "merkleRoot": merkle_tree.root
            },
            "issuanceDate": now.isoformat(),
            "expirationDate": expiration_date.isoformat(),
            "credentialStatus": {
                "id": f"https://blockchain.erasmus.eu/revocation/{credential_id}",
                "type": "RevocationList2020"
            },
            "proof": {
                "type": "RsaSignature2018",
                "created": now.isoformat(),
                "proofPurpose": "assertionMethod",
                "verificationMethod": f"{self.host_did}#key-1"
            }
        }

        # Firma digitale
        print("✍️  Processo di firma digitale:")
        print(f"   🔑 Firmata con DID: {self.host_did}")
        print(f"   🏛️  Emittente: Université de Rennes")
        print(f"   📊 Algoritmo: RS256 (RSA-2048 + SHA-256)")

        private_key_pem = self.host_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        credential_jwt = jwt.encode(
            vc_payload,
            private_key_pem,
            algorithm="RS256"
        )

        print(f"   📋 Token JWT generato: {len(credential_jwt)} caratteri")
        print()

        # Stampa riepilogo finale
        print("✅ CREDENZIALE EMESSA CON SUCCESSO")
        print("─" * 40)
        print(f"📋 ID Credenziale: {credential_id[:16]}...")
        print(f"🌳 Merkle Root: {merkle_tree.root[:16]}...")
        print(f"🔒 Stato sicurezza: Firmata digitalmente")
        print(f"📊 Stato blockchain: Pronta per registrazione")
        print(f"⏰ Validità: {(expiration_date - now).days} giorni")
        return credential_jwt

    def create_verifiable_presentation(self, credential_jwt: str,
                                       student_data: Dict[str, Any],
                                       selected_attributes: List[str]) -> str:
        """Crea una Verifiable Presentation con divulgazione selettiva"""
        print("\n🔍 CREAZIONE VERIFIABLE PRESENTATION")
        print("=" * 50)

        # Crea il Merkle Tree dai dati originali per generare le prove
        merkle_tree = EnhancedMerkleTree(student_data)

        # Genera le Merkle Proofs per gli attributi selezionati
        merkle_proofs = []
        disclosed_attributes = {}

        flat_student_data = merkle_tree._flatten_dict(student_data)
        for attribute in selected_attributes:
            proof = merkle_tree.calculate_merkle_proof(attribute)
            if proof:
                merkle_proofs.append(proof)
                disclosed_attributes[attribute] = flat_student_data.get(attribute)

        # Genera nonce per anti-replay
        nonce = self.csprng.generate_nonce()

        # Decodifica la credenziale originale
        original_vc = jwt.decode(credential_jwt, options={"verify_signature": False})

        # Crea la Verifiable Presentation
        now = datetime.now()
        vp_payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/presentations/v1"
            ],
            "id": f"https://erasmus.eu/presentations/{uuid.uuid4()}",
            "type": ["VerifiablePresentation"],
            "holder": self.student_did,
            "verifiableCredential": [{
                "originalCredentialJwt": credential_jwt,  # Include the original for simplicity
                "proof": {
                    "type": "MerkleTreeProof2020",
                    "merkleProofs": merkle_proofs
                }
            }],
            "proof": {
                "type": "RsaSignature2018",
                "created": now.isoformat(),
                "proofPurpose": "authentication",
                "verificationMethod": f"{self.student_did}#key-1",
                "nonce": nonce
            }
        }

        # Firma la VP con la chiave dello studente
        student_private_key_pem = self.student_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        vp_jwt = jwt.encode(vp_payload, student_private_key_pem, algorithm="RS256")

        print(f"✅ Verifiable Presentation creata")
        print(f"📊 Attributi divulgati: {len(disclosed_attributes)}")
        print(f"🎯 Nonce: {nonce[:16]}...")

        return vp_jwt

    def transmit_vc_with_hybrid_encryption(self, vc_jwt: str, student_data_full: Dict[str, Any]) -> Dict[str, str]:
        """
        Cifra la Verifiable Credential JWT e i dati completi dello studente
        utilizzando crittografia ibrida per la trasmissione sicura.
        Il pacchetto cifrato include sia il VC JWT che i dati completi.
        """
        print("\n🔐 TRASMISSIONE VC CON CRITTOGRAFIA IBRIDA")
        print("=" * 50)

        # Prepara il "contenitore" per i dati da cifrare: JWT e dati completi
        # Vogliamo che l'intero oggetto sia cifrato insieme
        data_to_encrypt = {
            "vc_jwt": vc_jwt,
            "student_data_full": student_data_full  # Includi i dati completi qui
        }
        # Converti il dizionario in una stringa JSON prima di cifrarlo
        data_to_encrypt_json = json.dumps(data_to_encrypt)

        # Cifratura ibrida del pacchetto completo
        encrypted_package = self.hybrid_crypto.encrypt_hybrid(
            data_to_encrypt_json.encode('utf-8'), self.student_public_key
        )

        print("✅ Verifiable Credential JWT e dati completi cifrati con AES-CTR")
        print("✅ Chiave di sessione cifrata con RSA-OAEP")
        print("📤 Pacchetto cifrato pronto per la trasmissione allo studente")
        return encrypted_package

    def verify_verifiable_credential(self, encrypted_package: Dict[str, str]) -> Dict[str, Any]:
        """
        Decifra e verifica completa della Verifiable Credential e dei dati completi.
        Include la verifica della firma dell'emittente e il ricalcolo della Merkle Root
        dai dati in chiaro forniti per confronto.
        """
        print("\n🔍 VERIFICA E DECIFRATURA VC DA PARTE DELLO STUDENTE")
        print("=" * 50)

        try:
            # Fase 1: Decifratura ibrida
            print("1. 🔓 Decifratura del pacchetto ricevuto...")
            decrypted_data_json = self.hybrid_crypto.decrypt_hybrid(
                encrypted_package, self.student_private_key
            ).decode('utf-8')

            # Converti la stringa JSON decifrata in un dizionario
            decrypted_data = json.loads(decrypted_data_json)
            decrypted_vc_jwt = decrypted_data["vc_jwt"]
            received_student_data_full = decrypted_data["student_data_full"]  # Estrai i dati completi

            # Fase 2: Verifica firma dell'università ospitante sulla VC JWT
            print("2. ✍️  Verifica della firma dell'università ospitante sulla VC JWT...")
            issuer_public_key = self.did_manager.get_public_key(self.host_did)
            issuer_public_key_pem = issuer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Decodifica il VC JWT per ottenerne il payload (che contiene la merkleRoot originale)
            vc_payload = jwt.decode(decrypted_vc_jwt, issuer_public_key_pem, algorithms=["RS256"])
            print("✅ Firma dell'emittente verificata con successo")

            # Fase 3: Verifica validità temporale
            print("3. ⏰ Verifica validità temporale...")
            current_time = datetime.now()
            issuance_date = datetime.fromisoformat(vc_payload["issuanceDate"])
            expiration_date = datetime.fromisoformat(vc_payload["expirationDate"])

            if not (issuance_date <= current_time <= expiration_date):
                print("❌ ERRORE: Credenziale non valida per data (scaduta o non ancora valida)")
                return None
            print("✅ Credenziale ancora valida")

            # Fase 4: Verifica dello stato di revoca
            print("4. 📜 Verifica dello stato di revoca...")
            credential_id = vc_payload["id"].split("/")[-1]
            if self.revocation_registry.is_revoked(credential_id):
                print(f"❌ ERRORE: La credenziale {credential_id[:16]}... risulta revocata!")
                return None
            print("✅ Credenziale non revocata")

            # *** NUOVA FASE CRUCIALE: Ricalcolo e Confronto Merkle Root ***
            print("5. 🌳 Ricalcolo e confronto della Merkle Root dai dati completi ricevuti...")
            # Qui devi ricostruire un Merkle Tree dai 'received_student_data_full'
            # e confrontare la sua radice con 'vc_payload["credentialSubject"]["merkleRoot"]'.

            # Crea un Merkle Tree temporaneo con i dati completi ricevuti
            temp_merkle_tree_from_received_data = EnhancedMerkleTree(received_student_data_full)
            recalculated_merkle_root = temp_merkle_tree_from_received_data.root

            original_merkle_root_in_vc = vc_payload["credentialSubject"]["merkleRoot"]

            if recalculated_merkle_root != original_merkle_root_in_vc:
                print(f"❌ ERRORE: Merkle Root non corrispondente!")
                print(f"   Ricalcolata: {recalculated_merkle_root[:16]}...")
                print(f"   Nel VC: {original_merkle_root_in_vc[:16]}...")
                return None
            print("✅ Merkle Root ricalcolata e corrispondente. Dati completi verificati!")
            # *** FINE NUOVA FASE ***

            print("\n🎉 VERIFICA VC COMPLETATA CON SUCCESSO!")
            print("✅ Lo studente ha ricevuto e verificato la credenziale e i suoi dati completi.")

            # Restituisci un dizionario contenente sia il JWT decifrato che i dati completi
            # per uso futuro (es. creazione VP, conservazione).
            return {
                "vc_jwt": decrypted_vc_jwt,
                "student_data_full": received_student_data_full,
                "vc_payload": vc_payload  # Utile per accedere direttamente al payload verificato
            }

        except jwt.exceptions.InvalidSignatureError as e:
            print(f"❌ ERRORE DI FIRMA nella VC: {str(e)}")
            return None
        except jwt.exceptions.ExpiredSignatureError as e:
            print(f"❌ ERRORE: VC Token scaduto: {str(e)}")
            return None
        except jwt.exceptions.DecodeError as e:
            print(f"❌ ERRORE: VC Token malformato o errore di decifratura: {str(e)}")
            return None
        except Exception as e:
            print(f"❌ ERRORE IMPREVISTO nella verifica VC: {str(e)}")
            return None

    def transmit_vp_with_hybrid_encryption(self, vp_jwt: str) -> Dict[str, str]:
        """Trasmissione sicura della VP con crittografia ibrida"""
        print("🔐 TRASMISSIONE VP CON CRITTOGRAFIA IBRIDA")
        print("=" * 50)

        # Cifra la VP con crittografia ibrida usando la chiave pubblica dell'università di origine
        vp_bytes = vp_jwt.encode('utf-8')
        encrypted_package = self.hybrid_crypto.encrypt_hybrid(
            vp_bytes, self.home_public_key
        )

        print("✅ Verifiable Presentation cifrata con AES-CTR")
        print("✅ Chiave di sessione cifrata con RSA-OAEP")
        print("📤 Pacchetto cifrato pronto per la trasmissione all'università di origine")

        return encrypted_package

    def verify_verifiable_presentation(self, encrypted_package: Dict[str, str]) -> bool:
        """Verifica completa della Verifiable Presentation"""
        print("\n🕵️  VERIFICA VERIFIABLE PRESENTATION")
        print("=" * 50)

        try:
            # Fase 1: Decifratura ibrida
            print("1. 🔓 Decifratura del pacchetto ricevuto...")
            decrypted_vp_jwt = self.hybrid_crypto.decrypt_hybrid(
                encrypted_package, self.home_private_key
            ).decode('utf-8')

            # Fase 2: Verifica firma dello studente e anti-replay sulla VP
            print("2. ✍️  Verifica della firma dello studente e del nonce...")
            student_public_key = self.did_manager.get_public_key(self.student_did)
            student_public_key_pem = student_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            vp_payload = jwt.decode(decrypted_vp_jwt, student_public_key_pem, algorithms=["RS256"])

            nonce = vp_payload["proof"]["nonce"]
            if nonce in self.used_nonces:
                print("❌ ERRORE: Nonce già utilizzato (possibile replay attack)")
                return False
            # Aggiungi il nonce a quelli usati SOLO se la verifica prosegue con successo

            print("✅ Firma dello studente verificata")
            print("✅ Verifica anti-replay completata")

            # Fase 3: Estrazione della VC originale e verifica della firma dell'emittente
            print("3. 🏛️  Verifica della credenziale originale dell'emittente...")
            vc_jwt = vp_payload["verifiableCredential"][0]["originalCredentialJwt"]
            issuer_public_key = self.did_manager.get_public_key(self.host_did)
            issuer_public_key_pem = issuer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            vc_payload = jwt.decode(vc_jwt, issuer_public_key_pem, algorithms=["RS256"])
            print("✅ Firma dell'emittente (Università Ospitante) verificata")

            # Fase 4: Verifica dello stato di revoca
            print("4. 📜 Verifica dello stato di revoca...")
            credential_id = vc_payload["id"].split("/")[-1]
            if self.revocation_registry.is_revoked(credential_id):
                print(f"❌ ERRORE: La credenziale {credential_id[:16]}... risulta revocata!")
                return False
            print("✅ Credenziale non revocata")

            # Fase 5: Verifica delle Merkle Proofs
            print("5. 🌳 Verifica delle Merkle Proofs...")
            merkle_proofs = vp_payload["verifiableCredential"][0]["proof"]["merkleProofs"]
            merkle_root_from_vc = vc_payload["credentialSubject"]["merkleRoot"]

            # Crea un Merkle Tree temporaneo con la root originale per la verifica
            temp_tree = EnhancedMerkleTree({"temp": "data"})
            temp_tree.root = merkle_root_from_vc

            all_proofs_valid = True
            for proof in merkle_proofs:
                if not temp_tree.verify_merkle_proof(proof):
                    all_proofs_valid = False
                    break

            if not all_proofs_valid:
                print("❌ ERRORE: Una o più Merkle Proofs non sono valide.")
                return False
            print("✅ Tutte le Merkle Proofs sono state verificate con successo")

            # Se tutto è andato a buon fine, aggiungi il nonce a quelli usati
            self.used_nonces.add(nonce)

            print("\n🎉 VERIFICA COMPLETATA CON SUCCESSO!")
            return True

        except jwt.exceptions.InvalidSignatureError as e:
            print(f"❌ ERRORE DI FIRMA: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ ERRORE IMPREVISTO nella verifica: {str(e)}")
            return False
        except jwt.exceptions.ExpiredSignatureError as e:
            print(f"❌ ERRORE: Token scaduto: {str(e)}")
            return False
        except jwt.exceptions.DecodeError as e:
            print(f"❌ ERRORE: Token malformato: {str(e)}")
            return False

    def demonstrate_credential_storage(self, credential_jwt: str):
        """
        Dimostra il processo di conservazione e archiviazione delle credenziali
        come gestito da una DApp nel wallet dello studente.
        """
        print("\n💾 PROCESSO DI CONSERVAZIONE CREDENZIALI")
        print("=" * 50)

        # La DApp decodifica il JWT per analizzare la credenziale
        try:
            vc_payload = jwt.decode(credential_jwt, options={"verify_signature": False})
            credential_id = vc_payload["id"].split("/")[-1]
        except Exception as e:
            print(f"❌ ERRORE: Impossibile decodificare il JWT della credenziale per l'analisi: {e}")
            return None  # Esci se non riusciamo ad analizzare la credenziale

        print("📋 Analisi della credenziale da conservare tramite DApp:")
        print(f"   🆔 ID: {credential_id}")
        print(f"   👤 Soggetto: {vc_payload['credentialSubject']['id']}")
        print(f"   🏛️  Emittente: {vc_payload['issuer']['name']}")
        print(f"   📅 Emessa il: {vc_payload['issuanceDate']}")
        print(f"   ⏰ Scade il: {vc_payload['expirationDate']}")
        print()

        print("🔄 La DApp avvia il processo di backup e archiviazione:")

        # Backup Locale gestito dalla DApp
        print("   📱 DApp: Creazione backup locale della credenziale...")
        time.sleep(0.5)  # Simula elaborazione
        # In una vera DApp, qui si salverebbe il JWT cifrato in una memoria locale sicura (es. KeyStore)
        print("   ✅ DApp: Backup locale completato")

        # Sincronizzazione Cloud (opzionale, gestita dalla DApp)
        print("   ☁️  DApp: Sincronizzazione cloud (opzionale) in corso...")
        time.sleep(0.5)
        # Una DApp potrebbe integrare servizi cloud cifrati per backup utente
        print("   ✅ DApp: Sincronizzazione cloud completata")

        # Crittografia del backup (la DApp si assicura che i dati siano cifrati prima dello storage)
        print("   🔐 DApp: Crittografia del backup con chiave utente...")
        time.sleep(0.5)
        # I dati sarebbero già stati cifrati dal meccanismo ibrido, qui si simula la cifratura a riposo.
        # In un wallet reale, il JWT potrebbe essere ulteriormente cifrato con una chiave derivata dalla password utente.
        print("   ✅ DApp: Backup crittografato")

        # Registrazione su Blockchain (per metadati o hash, non l'intera VC)
        print("   📊 DApp: Registrazione di metadati o hash su blockchain per tracciabilità...")
        time.sleep(0.5)
        # Una DApp potrebbe registrare l'hash della VC o un riferimento alla sua esistenza su una blockchain
        # per scopi di auditing o per un indice pubblico (non la VC stessa per privacy).
        # Per semplicità, qui simuliamo solo la conferma della transazione.
        print("   ✅ DApp: Transazione blockchain confermata")

        # Metadati di conservazione gestiti e visualizzati dalla DApp
        storage_metadata = {
            "credential_id": credential_id,
            "storage_date": datetime.now().isoformat(),
            "managed_by": "Student's DApp/Digital Wallet",  # Indichiamo che è la DApp a gestire
            "backup_locations": ["local_device_storage", "encrypted_cloud_storage", "blockchain_record"],
            "encryption_status": "AES-256 encrypted (at rest)",
            "integrity_check": "SHA-256 verified (on receipt)",  # Riflette la verifica già fatta
            "access_level": "restricted_to_owner"
        }

        print()
        print("📊 METADATI DI CONSERVAZIONE GESTITI DALLA DApp:")
        print("─" * 40)
        for key, value in storage_metadata.items():
            print(f"   {key}: {value}")

        print()
        print("✅ CONSERVAZIONE COMPLETATA CON SUCCESSO TRAMITE DApp!")
        print("🔒 La credenziale è ora archiviata in modo sicuro nel wallet digitale dello studente.")

        return storage_metadata

    def _flatten_data_for_display(self, data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """Appiattisce un dizionario nested per recuperare tutti i percorsi individuali."""
        items = {}
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                items.update(self._flatten_data_for_display(value, new_key))
            elif isinstance(value, list):
                # Quando incontriamo una lista, ogni elemento (se dizionario) può essere un blocco
                # Non vogliamo che la lista stessa sia una "foglia" appiattita se contiene dizionari
                is_list_of_dicts = any(isinstance(item, dict) for item in value)
                if is_list_of_dicts:
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            block_item_prefix = f"{new_key}[{i + 1}]"  # es: erasmusInfo.learningAgreement.courses[1]
                            items.update(self._flatten_data_for_display(item, block_item_prefix))
                        else:
                            # Se la lista contiene elementi non-dict, li appiattiamo con indice
                            items[f"{new_key}[{i + 1}]"] = item
                else:  # Se la lista contiene solo elementi semplici, appiattiamo la lista stessa
                    items[new_key] = value  # Potrebbe essere un percorso come 'skills: [A, B]'
            else:
                items[new_key] = value
        return items

    def _simulate_dapp_attribute_selection(self, student_data_full: Dict[str, Any]) -> List[str]:
        """
        Simula l'interfaccia di una DApp per la selezione degli attributi,
        presentando un'unica lista di opzioni (blocchi con dettagli e attributi singoli).
        """
        print("\n" + "=" * 70)
        print("📱 DApp: INTERFACCIA WALLET STUDENTE - DIVULGAZIONE SELETTIVA")
        print("=" * 70)
        print("Carissimo studente, questa è la tua Verifiable Credential Erasmus.")
        print("Scegli attentamente quali informazioni vuoi condividere con l'Università di Origine.")
        print("Puoi selezionare interi blocchi (corsi/certificati) con tutti i loro dettagli,")
        print("o singoli attributi specifici non facenti parte di un blocco.")
        print(" ")

        # Filtra i dati per includere solo le sezioni rilevanti per la selezione
        filtered_data_for_selection = {}
        if "erasmusInfo" in student_data_full:
            filtered_data_for_selection["erasmusInfo"] = student_data_full["erasmusInfo"]
        if "languageCertificates" in student_data_full:
            filtered_data_for_selection["languageCertificates"] = student_data_full["languageCertificates"]

        if not filtered_data_for_selection:
            print("⚠️ Nessuna informazione Erasmus o certificato linguistico disponibile per la selezione.")
            print("=" * 70)
            return []

        # Appiattisce tutti i dati filtrati per avere tutti i percorsi individuali disponibili.
        # Questa sarà la fonte per espandere i blocchi e trovare gli attributi singoli "puri".
        all_flat_attributes = self._flatten_data_for_display(filtered_data_for_selection)

        all_selectable_options = []

        # --- Identificazione e Preparazione dei BLOCCHI (Corsi e Certificati) ---

        # Processa erasmusInfo.learningAgreement.courses
        courses = filtered_data_for_selection.get("erasmusInfo", {}).get("learningAgreement", {}).get("courses", [])
        for i, course_data in enumerate(courses):
            course_name = course_data.get("courseName", "Sconosciuto")
            block_path_prefix = f"erasmusInfo.learningAgreement.courses[{i + 1}]"
            all_selectable_options.append({
                "type": "block",
                "display_title": f"Corso {i + 1}: {course_name}",
                "data_path_prefix": block_path_prefix,
                "source_data": course_data
            })

        # Processa languageCertificates
        certs = filtered_data_for_selection.get("erasmusInfo", {}).get("languageCertificates", [])
        for i, cert_data in enumerate(certs):
            cert_lang = cert_data.get("language", "Sconosciuta")
            cert_level = cert_data.get("level", "N/A")
            block_path_prefix = f"erasmusInfo.languageCertificates[{i + 1}]"
            all_selectable_options.append({
                "type": "block",
                "display_title": f"Certificato {i + 1}: {cert_lang} ({cert_level})",
                "data_path_prefix": block_path_prefix,
                "source_data": cert_data
            })

        # --- Identificazione e Preparazione degli ATTRIBUTI SINGOLI ---
        # Creiamo un set di tutti i prefissi dei blocchi per un controllo efficiente
        block_prefixes = {opt["data_path_prefix"] for opt in all_selectable_options if opt["type"] == "block"}

        # Identifica tutti i percorsi che fanno parte di un blocco completo
        # useremo questo per escluderli dalle opzioni "singole"
        paths_already_in_blocks = set()
        for bp in block_prefixes:
            for attr_path in all_flat_attributes.keys():
                if attr_path.startswith(bp):
                    paths_already_in_blocks.add(attr_path)

        for attr_path, attr_value in all_flat_attributes.items():
            # Un attributo è considerato "singolo" se non è già stato identificato come parte di un blocco
            # e non è una struttura complessa (dict o list, che dovrebbero essere gestite come blocchi o liste di blocchi)
            if attr_path not in paths_already_in_blocks and not isinstance(attr_value, (dict, list)):
                # Ulteriore controllo per escludere i percorsi radice delle liste di blocchi, se fossero appiattite
                if attr_path != "erasmusInfo.learningAgreement.courses" and \
                        attr_path != "erasmusInfo.languageCertificates":
                    all_selectable_options.append({
                        "type": "single",
                        "display_title": f"{attr_path}: {attr_value}",
                        "data_path": attr_path,
                        "source_data": attr_value
                    })

        # Ordina l'unica lista di opzioni per la visualizzazione.
        # Preferiamo i blocchi all'inizio, poi gli attributi singoli, e poi in ordine alfabetico.
        # Ordine: [Blocchi, Singoli] -> all'interno di ogni gruppo, per display_title
        all_selectable_options.sort(key=lambda x: (x["type"] != "block", x["display_title"]))

        # --- Visualizzazione delle Opzioni in una Lista Unificata ---
        all_options_map = {}
        display_index = 1

        print("\n" + "=" * 30)
        print("TUTTE LE OPZIONI DI SELEZIONE:")
        print("=" * 30)

        if not all_selectable_options:
            print("  Nessuna opzione di condivisione disponibile.")
        else:
            for option in all_selectable_options:
                all_options_map[display_index] = option

                # Stampa il titolo principale dell'opzione
                print(f"  [{display_index}] {option['display_title']}")

                # Se l'opzione è un blocco (corso o certificato), stampa i suoi dettagli annidati
                if option["type"] == "block":
                    # Re-appiattisci solo il dizionario sorgente del blocco per ottenere i suoi dettagli interni
                    # Usiamo un prefisso vuoto per ottenere solo i nomi dei campi puliti (es. 'courseName', 'language')
                    temp_flat_details = self._flatten_data_for_display(option["source_data"])

                    # Ordina i dettagli per una visualizzazione più pulita
                    for detail_key_raw in sorted(temp_flat_details.keys()):
                        print(f"    - {detail_key_raw}: {temp_flat_details[detail_key_raw]}")
                    print("    " + "-" * 20)  # Separatore visivo per i dettagli del blocco

                display_index += 1
        print("=" * 30)  # Chiusura della sezione opzioni

        print("\nINSTRUZIONI:")
        print("  - Digita uno o più numeri separati da spazio (es. '1 5 12').")
        print("  - Digita 'fatto' o 'F' per terminare la selezione.")
        print("  - Digita 'reset' per cancellare tutte le selezioni attuali.")
        print("-" * 30)

        selected_by_user_paths = set()
        selected_by_user_display = []

        while True:
            print("\n" + "=" * 30)
            print("LE TUE SELEZIONI ATTUALI:")
            print("-" * 30)
            if not selected_by_user_display:
                print("  Nessun attributo selezionato finora.")
            else:
                for idx, attr_display_str in enumerate(selected_by_user_display):
                    print(f"  {idx + 1}. {attr_display_str}")
            print("=" * 30)

            user_input = input("\nSeleziona opzioni (numeri) o 'fatto'/'F'/'reset': ").strip().lower()

            if user_input in ['fatto', 'f']:
                break
            elif user_input == 'reset':
                selected_by_user_paths = set()
                selected_by_user_display = []
                print("🗑️ Tutte le selezioni sono state resettate.")
                continue

            choices = user_input.replace(',', ' ').split()

            newly_added_count = 0
            for choice_str in choices:
                try:
                    choice_num = int(choice_str)
                    option = all_options_map.get(choice_num)

                    if option:
                        if option["type"] == "block":
                            # Quando un blocco è selezionato, aggiungiamo tutti i suoi attributi figli.
                            # Usiamo il prefisso del blocco per filtrare dalla lista appiattita completa.
                            paths_in_block = [p for p in all_flat_attributes.keys() if
                                              p.startswith(option["data_path_prefix"])]

                            for path in paths_in_block:
                                if path not in selected_by_user_paths:
                                    selected_by_user_paths.add(path)
                                    selected_by_user_display.append(f"{path}: {all_flat_attributes[path]}")
                                    newly_added_count += 1
                            print(f"✅ Blocco '{option['display_title']}' aggiunto con tutti i suoi attributi.")

                        elif option["type"] == "single":
                            path = option["data_path"]
                            if path not in selected_by_user_paths:
                                selected_by_user_paths.add(path)
                                selected_by_user_display.append(option["display_title"])
                                newly_added_count += 1
                                print(f"✅ Hai aggiunto: {option['display_title']}")
                            else:
                                print(
                                    f"⚠️ {option['display_title']} (numero {choice_num}) era già selezionato. Saltato.")
                    else:
                        print(f"❌ Numero {choice_num} non valido. Riprova.")
                except ValueError:
                    print(f"❌ Input '{choice_str}' non valido. Digita un numero, 'fatto', 'F' o 'reset'.")
                except Exception as e:
                    print(f"❌ Errore durante l'elaborazione di '{choice_str}': {e}")

            if newly_added_count > 0:
                print(f"✅ Aggiunti {newly_added_count} nuovi attributi.")

        print("\n" + "=" * 70)
        if not selected_by_user_paths:
            print("⚠️ Nessun attributo selezionato. La presentazione sarà vuota.")
        else:
            print("👍 Selezione completata! La tua Verifiable Presentation includerà:")
            # Stampa gli attributi selezionati in ordine alfabetico per una migliore leggibilità finale
            for attr_path in sorted(list(selected_by_user_paths)):
                print(f"  - {attr_path}: {all_flat_attributes.get(attr_path, 'N/A')}")
        print("=" * 70)

        return list(selected_by_user_paths)

    def demonstrate_revocation_process(self, credential_jwt: str):
        """Dimostra il processo di revoca"""
        print("\n🚫 PROCESSO DI REVOCA")
        print("=" * 50)

        # Decodifica per ottenere l'ID
        vc_payload = jwt.decode(credential_jwt, options={"verify_signature": False})
        credential_id = vc_payload["id"].split("/")[-1]

        # Simula la firma della revoca da parte dell'emittente
        revocation_data = f"REVOKE:{credential_id}:{datetime.now().isoformat()}"
        signature = base64.b64encode(
            self.host_private_key.sign(
                revocation_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        ).decode()

        # Registra la revoca
        self.revocation_registry.revoke_credential(
            credential_id, self.host_did, signature, "Academic misconduct"
        )

        return credential_id

def main():
    """Funzione principale per testare il sistema migliorato"""
    print("🎓 SISTEMA AVANZATO DI CREDENZIALI ERASMUS")
    print("=" * 60)
    print("Implementazione conforme agli standard W3C")
    print("Con tecnologie: DID, VC, Merkle Tree, Crittografia Ibrida")
    print("=" * 60)
    print("\n")

    # Inizializza il sistema
    system = EnhancedErasmusCredentialSystem()
    print("\n")

    # Crea i dati dettagliati dello studente
    student_data = system.create_detailed_student_data() # Questo è il set completo di dati
    print("\n")

    # 1. EMISSIONE VERIFIABLE CREDENTIAL
    # L'università ospitante (Rennes) emette la credenziale allo studente
    vc_jwt = system.issue_verifiable_credential(student_data)

    # 2. TRASMISSIONE SICURA VC: UNIVERSITÀ OSPITANTE → STUDENTE
    print("\n📤 TRASMISSIONE VERIFIABLE CREDENTIAL")
    print("🏛️  Università Ospitante (Rennes) → 👤 Studente (Mario Rossi)")
    print("=" * 60)

    # Cifra la VC con crittografia ibrida E i dati completi dello studente
    encrypted_vc_package = system.transmit_vc_with_hybrid_encryption(vc_jwt, student_data)

    # 3. RICEZIONE E VERIFICA VC DA PARTE DELLO STUDENTE
    print("\n📥 RICEZIONE E VERIFICA VC DA PARTE DELLO STUDENTE")
    print("=" * 60)

    # Lo studente riceve, decifra e verifica la VC e i dati completi.
    # Ora 'verified_vc_data' sarà un dizionario con 'vc_jwt', 'student_data_full', 'vc_payload'
    verified_vc_data = system.verify_verifiable_credential(encrypted_vc_package)

    if not verified_vc_data:
        print("❌ ERRORE: Impossibile verificare la VC ricevuta. La conservazione e la creazione della VP non avverranno.")
        return # Esce se la verifica fallisce

    # Estrai i componenti dal dizionario verificato
    decrypted_vc_jwt = verified_vc_data["vc_jwt"]
    student_data_verified = verified_vc_data["student_data_full"] # I dati completi ora verificati dallo studente
    # Se ti servisse il payload decodificato della VC: vc_payload = verified_vc_data["vc_payload"]

    # 4. CONSERVAZIONE VC DA PARTE DELLO STUDENTE
    print("\n💾 LO STUDENTE CONSERVA LA CREDENZIALE RICEVUTA E VERIFICATA")
    print("=" * 60)
    system.demonstrate_credential_storage(decrypted_vc_jwt)
    print("\n")

    # 5. DIVULGAZIONE SELETTIVA E PRESENTAZIONE (ORA CON SELEZIONE DAPP SIMULATA)
    print("\n🎯 CREAZIONE VERIFIABLE PRESENTATION (TRAMITE DApp)")
    print("👤 Studente (Mario Rossi) → 🏛️  Università di Origine (Salerno)")
    print("=" * 60)

    # *** NUOVA CHIAMATA AL METODO INTERNO DELLA CLASSE PER SIMULARE LA SELEZIONE DAPP ***
    selected_attributes = system._simulate_dapp_attribute_selection(student_data_verified)

    if not selected_attributes:
        print("\n🚫 Nessun attributo selezionato. Annullamento creazione Verifiable Presentation.")
        return  # Esce se non viene selezionato nulla

    vp_jwt_first_presentation = system.create_verifiable_presentation(
        decrypted_vc_jwt, student_data_verified, selected_attributes
    )

    # 6. TRASMISSIONE SICURA VP: STUDENTE → UNIVERSITÀ DI ORIGINE
    print("\n📤 TRASMISSIONE VERIFIABLE PRESENTATION")
    print("👤 Studente (Mario Rossi) → 🏛️  Università di Origine (Salerno)")
    print("=" * 60)

    encrypted_package_first_presentation = system.transmit_vp_with_hybrid_encryption(vp_jwt_first_presentation)
    print("\n")

    # 7. VERIFICA DA PARTE DEL DESTINATARIO (UNIVERSITÀ DI ORIGINE)
    print("🔍 VERIFICA DA PARTE DELL'UNIVERSITÀ DI ORIGINE")
    print("=" * 60)
    is_valid = system.verify_verifiable_presentation(encrypted_package_first_presentation)
    print(f"\nRisultato della prima verifica: {'VALIDA ✅' if is_valid else 'NON VALIDA ❌'}")
    print("\n")

    # 8. PROCESSO DI REVOCA
    print("🚫 SIMULAZIONE PROCESSO DI REVOCA")
    print("=" * 60)
    revoked_credential_id = system.demonstrate_revocation_process(decrypted_vc_jwt)
    print(f"Credenziale ID '{revoked_credential_id[:16]}...' è stata revocata.")
    print("\n")

    # 9. SECONDO TENTATIVO DI VERIFICA (Generando una NUOVA presentazione)
    print("🔄 TENTATIVO DI VERIFICA POST-REVOCA")
    print("=" * 60)
    print("Tentativo di riverificare la stessa credenziale con una NUOVA presentazione dopo la revoca...")

    # Crea una NUOVA presentazione dalla stessa VC, usando i dati verificati dallo studente
    vp_jwt_second_presentation = system.create_verifiable_presentation(
        decrypted_vc_jwt, student_data_verified, selected_attributes
    )
    # E poi cifra questa nuova presentazione
    encrypted_package_second_presentation = system.transmit_vp_with_hybrid_encryption(vp_jwt_second_presentation)

    is_still_valid = system.verify_verifiable_presentation(encrypted_package_second_presentation)
    print(f"\nRisultato della seconda verifica (post-revoca): {'VALIDA ✅' if is_still_valid else 'NON VALIDA ❌'}")

    # 10. RIEPILOGO FINALE
    print("\n📊 RIEPILOGO DEL PROCESSO COMPLETO")
    print("=" * 60)
    print("1. ✅ Emissione VC da Università Ospitante")
    print("2. ✅ Trasmissione cifrata VC e Dati Completi → Studente")
    print("3. ✅ Verifica, Decifratura e Ricalcolo Merkle Root da parte dello Studente")
    print("4. ✅ Conservazione VC da parte dello Studente (solo se verificata)")
    print("5. ✅ Creazione VP con divulgazione selettiva")
    print("6. ✅ Trasmissione cifrata VP → Università di Origine")
    print("7. ✅ Verifica VP da parte dell'Università di Origine")
    print("8. ✅ Processo di revoca simulato")
    print("9. ✅ Verifica post-revoca (fallimento atteso)")
    print("\n🎉 DIMOSTRAZIONE COMPLETA DEL SISTEMA ERASMUS!")


if __name__ == "__main__":
    main()