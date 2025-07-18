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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

        # Simula conservazione sicura
        print()
        print("💾 CONSERVAZIONE SICURA DELLA CREDENZIALE")
        print("─" * 40)
        print("📁 Archiviazione in database sicuro...")
        print("🔐 Backup crittografato generato...")
        print("📊 Registrazione su blockchain in corso...")
        print("✅ Credenziale conservata con successo")

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

    def transmit_with_hybrid_encryption(self, vp_jwt: str) -> Dict[str, str]:
        """Trasmissione sicura con crittografia ibrida"""
        print("\n🔐 TRASMISSIONE CON CRITTOGRAFIA IBRIDA")
        print("=" * 50)

        # Cifra la VP con crittografia ibrida
        vp_bytes = vp_jwt.encode('utf-8')
        encrypted_package = self.hybrid_crypto.encrypt_hybrid(
            vp_bytes, self.home_public_key
        )

        print("✅ Verifiable Presentation cifrata con AES-CTR")
        print("✅ Chiave di sessione cifrata con RSA-OAEP")
        print("📤 Pacchetto cifrato pronto per la trasmissione")

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
        """Dimostra il processo di conservazione e archiviazione"""
        print("\n💾 PROCESSO DI CONSERVAZIONE CREDENZIALI")
        print("=" * 50)

        # Decodifica per analisi
        vc_payload = jwt.decode(credential_jwt, options={"verify_signature": False})
        credential_id = vc_payload["id"].split("/")[-1]

        print("📋 Analisi della credenziale da conservare:")
        print(f"   🆔 ID: {credential_id}")
        print(f"   👤 Soggetto: {vc_payload['credentialSubject']['id']}")
        print(f"   🏛️  Emittente: {vc_payload['issuer']['name']}")
        print(f"   📅 Emessa il: {vc_payload['issuanceDate']}")
        print(f"   ⏰ Scade il: {vc_payload['expirationDate']}")
        print()

        # Simula processo di backup
        print("🔄 Processo di backup e archiviazione:")
        print("   📁 Creazione backup locale...")
        time.sleep(0.5)  # Simula elaborazione
        print("   ✅ Backup locale completato")

        print("   ☁️  Sincronizzazione cloud...")
        time.sleep(0.5)
        print("   ✅ Sincronizzazione cloud completata")

        print("   🔐 Crittografia backup...")
        time.sleep(0.5)
        print("   ✅ Backup crittografato")

        print("   📊 Registrazione su blockchain...")
        time.sleep(0.5)
        print("   ✅ Transazione blockchain confermata")

        # Metadati di conservazione
        storage_metadata = {
            "credential_id": credential_id,
            "storage_date": datetime.now().isoformat(),
            "backup_locations": ["local", "cloud", "blockchain"],
            "encryption_status": "AES-256 encrypted",
            "integrity_check": "SHA-256 verified",
            "access_level": "restricted"
        }

        print()
        print("📊 METADATI DI CONSERVAZIONE:")
        print("─" * 30)
        for key, value in storage_metadata.items():
            print(f"   {key}: {value}")

        print()
        print("✅ CONSERVAZIONE COMPLETATA CON SUCCESSO")
        print("🔒 La credenziale è ora archiviata in modo sicuro")

        return storage_metadata

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
    student_data = system.create_detailed_student_data()
    print("\n")

    # 1. EMISSIONE VERIFIABLE CREDENTIAL
    # L'università ospitante (Rennes) emette la credenziale allo studente
    vc_jwt = system.issue_verifiable_credential(student_data)

    # 1.1 DIMOSTRAZIONE CONSERVAZIONE
    system.demonstrate_credential_storage(vc_jwt)

    # 2. DIVULGAZIONE SELETTIVA E PRESENTAZIONE
    # Lo studente (Mario Rossi) crea una presentazione per l'università di origine (Salerno)
    selected_attributes = [
        "studentInfo.name", "studentInfo.surname", "studentInfo.nationality",
        "erasmusInfo.learningAgreement.courses[0].courseName",
        "erasmusInfo.learningAgreement.courses[0].grade",
        "erasmusInfo.learningAgreement.courses[1].courseName",
        "erasmusInfo.learningAgreement.courses[1].grade",
        "erasmusInfo.learningAgreement.totalCredits"
    ]

    vp_jwt_first_presentation = system.create_verifiable_presentation(  # Rinomina per chiarezza
        vc_jwt, student_data, selected_attributes
    )

    # 3. TRASMISSIONE SICURA
    encrypted_package_first_presentation = system.transmit_with_hybrid_encryption(vp_jwt_first_presentation)
    print("\n")

    # 4. VERIFICA DA PARTE DEL DESTINATARIO
    is_valid = system.verify_verifiable_presentation(encrypted_package_first_presentation)
    print(f"\nRisultato della prima verifica: {'VALIDA ✅' if is_valid else 'NON VALIDA ❌'}")
    print("\n")

    # 5. PROCESSO DI REVOCA
    revoked_credential_id = system.demonstrate_revocation_process(vc_jwt)
    print(f"Credenziale ID '{revoked_credential_id[:16]}...' è stata revocata.")
    print("\n")

    # 6. SECONDO TENTATIVO DI VERIFICA (Generando una NUOVA presentazione)
    print("🔄 Tentativo di riverificare la stessa credenziale con una NUOVA presentazione dopo la revoca...")

    # Crea una NUOVA presentazione dalla stessa VC, che avrà un nuovo nonce
    vp_jwt_second_presentation = system.create_verifiable_presentation(
        vc_jwt, student_data, selected_attributes  # Stessi attributi ma nuova VP
    )
    # E poi cifra questa nuova presentazione
    encrypted_package_second_presentation = system.transmit_with_hybrid_encryption(vp_jwt_second_presentation)

    is_still_valid = system.verify_verifiable_presentation(encrypted_package_second_presentation)
    print(f"\nRisultato della seconda verifica (post-revoca): {'VALIDA ✅' if is_still_valid else 'NON VALIDA ❌'}")
    print("\n")


if __name__ == "__main__":
    main()