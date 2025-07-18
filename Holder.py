from DIDManager import EnhancedDIDManager
from HybridCrypto import HybridCrypto
from NumberGenerator import CSPRNGGenerator
from typing import Any, Optional, Dict, List
from RevocationRegistry import EnhancedRevocationRegistry
from cryptography.hazmat.primitives.asymmetric import rsa
import json
from datetime import datetime
import jwt
from cryptography.hazmat.primitives import serialization
from MerkleTree import EnhancedMerkleTree
import time
import uuid


class Holder:
    def __init__(self, did_manager: EnhancedDIDManager, hybrid_crypto: HybridCrypto, csprng: CSPRNGGenerator):
        self.did_manager = did_manager
        self.hybrid_crypto = hybrid_crypto
        self.csprng = csprng
        self.private_key: Any = None
        self.public_key: Any = None
        self.did: Optional[str] = None
        self.name: Optional[str] = None
        self.stored_vc: Optional[Dict[str, Any]] = None  # Per conservare la VC decifrata e i dati originali

    def generate_keys_and_did(self, name: str, entity_type: str = "student"):
        """Genera chiavi asimmetriche e DID per il detentore."""
        print(f"🔑 Generazione chiavi e DID per il Detentore: {name}...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.did = self.did_manager.create_did(name, entity_type, self.public_key)
        self.name = name
        print(f"✅ Chiavi generate e DID creato per {name}: {self.did}")

    def receive_and_verify_vc(self, encrypted_package: Dict[str, bytes],
                              issuer_public_key: Any, revocation_registry: EnhancedRevocationRegistry) -> bool:
        """
        Decifra e verifica completa della Verifiable Credential e dei dati completi.
        """
        print(f"\n🔍 VERIFICA E DECIFRATURA VC DA PARTE DELLO STUDENTE: {self.name}")
        print("=" * 50)

        if not self.private_key:
            raise Exception("Detentore non inizializzato: chiave privata mancante.")

        try:
            # Fase 1: Decifratura ibrida
            print("1. 🔓 Decifratura del pacchetto ricevuto...")
            decrypted_data_json = self.hybrid_crypto.decrypt_hybrid(
                encrypted_package, self.private_key
            ).decode('utf-8')

            decrypted_data = json.loads(decrypted_data_json)
            decrypted_vc_jwt = decrypted_data["vc_jwt"]
            received_student_data_full = decrypted_data["student_data_full"]

            # Fase 2: Verifica firma dell'università ospitante sulla VC JWT
            print("2. ✍️  Verifica della firma dell'emittente sulla VC JWT...")
            issuer_public_key_pem = issuer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            vc_payload = jwt.decode(decrypted_vc_jwt, issuer_public_key_pem, algorithms=["RS256"])
            print("✅ Firma dell'emittente verificata con successo")

            # Fase 3: Verifica validità temporale
            print("3. ⏰ Verifica validità temporale...")
            current_time = datetime.now()
            issuance_date = datetime.fromisoformat(vc_payload["issuanceDate"])
            expiration_date = datetime.fromisoformat(vc_payload["expirationDate"])

            if not (issuance_date <= current_time <= expiration_date):
                print("❌ ERRORE: Credenziale non valida per data (scaduta o non ancora valida)")
                return False
            print("✅ Credenziale ancora valida")

            # Fase 4: Verifica dello stato di revoca
            print("4. 📜 Verifica dello stato di revoca...")
            credential_id = vc_payload["id"].split("/")[-1]
            if revocation_registry.is_revoked(credential_id):
                print(f"❌ ERRORE: La credenziale {credential_id[:16]}... risulta revocata!")
                return False
            print("✅ Credenziale non revocata")

            # Fase 5: Ricalcolo e Confronto Merkle Root dai dati completi ricevuti
            print("5. 🌳 Ricalcolo e confronto della Merkle Root dai dati completi ricevuti...")
            temp_merkle_tree_from_received_data = EnhancedMerkleTree(received_student_data_full)
            recalculated_merkle_root = temp_merkle_tree_from_received_data.root
            original_merkle_root_in_vc = vc_payload["credentialSubject"]["merkleRoot"]

            if recalculated_merkle_root != original_merkle_root_in_vc:
                print(f"❌ ERRORE: Merkle Root non corrispondente!")
                print(f"   Ricalcolata: {recalculated_merkle_root[:16]}...")
                print(f"   Nel VC: {original_merkle_root_in_vc[:16]}...")
                return False
            print("✅ Merkle Root ricalcolata e corrispondente. Dati completi verificati!")

            print("\n🎉 VERIFICA VC COMPLETATA CON SUCCESSO!")
            print("✅ Lo studente ha ricevuto e verificato la credenziale e i suoi dati completi.")

            self.stored_vc = {
                "vc_jwt": decrypted_vc_jwt,
                "student_data_full": received_student_data_full,
                "vc_payload": vc_payload
            }
            return True

        except jwt.exceptions.InvalidSignatureError as e:
            print(f"❌ ERRORE DI FIRMA nella VC: {str(e)}")
            return False
        except jwt.exceptions.ExpiredSignatureError as e:
            print(f"❌ ERRORE: VC Token scaduto: {str(e)}")
            return False
        except jwt.exceptions.DecodeError as e:
            print(f"❌ ERRORE: VC Token malformato o errore di decifratura: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ ERRORE IMPREVISTO nella verifica VC: {str(e)}")
            return False

    def _flatten_data_for_display(self, data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Appiattisce un dizionario nested per recuperare tutti i percorsi individuali.
        Questa è una versione adattata per la visualizzazione nella DApp e per la corrispondenza
        con i percorsi del Merkle Tree (usa indici basati su 0).
        """
        items = {}
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                items.update(self._flatten_data_for_display(value, new_key))
            elif isinstance(value, list):
                for i, item_in_list in enumerate(value):
                    # USA INDICE BASATO SU 0 per la corrispondenza con MerkleTree
                    indexed_path = f"{new_key}[{i}]"
                    if isinstance(item_in_list, dict):
                        items.update(self._flatten_data_for_display(item_in_list, indexed_path))
                    else:
                        items[indexed_path] = item_in_list
            else:
                items[new_key] = value
        return items

    def select_attributes_for_vp(self) -> List[str]:
        """
        Simula l'interfaccia di una DApp per la selezione degli attributi,
        presentando un'unica lista di opzioni (blocchi con dettagli e attributi singoli).
        """
        if not self.stored_vc:
            print("⚠️ Nessuna Verifiable Credential conservata. Impossibile selezionare attributi.")
            return []

        student_data_full = self.stored_vc["student_data_full"]

        print("\n" + "=" * 70)
        print("📱 DApp: INTERFACCIA WALLET STUDENTE - DIVULGAZIONE SELETTIVA")
        print("=" * 70)
        print("Carissimo studente, questa è la tua Verifiable Credential Erasmus.")
        print("Scegli attentamente quali informazioni vuoi condividere con l'Università di Origine.")
        print("Puoi selezionare interi blocchi (corsi/certificati) con tutti i loro dettagli,")
        print("o singoli attributi specifici non facenti parte di un blocco.")
        print(" ")

        # Appiattisce tutti i dati per avere tutti i percorsi individuali disponibili.
        # Usa EnhancedMerkleTree._flatten_dict per garantire la coerenza dei percorsi
        # con la generazione delle Merkle Proofs.
        merkle_tree_for_paths = EnhancedMerkleTree(student_data_full)
        all_flat_attributes = merkle_tree_for_paths._flatten_dict(student_data_full)


        all_selectable_options = []

        # --- Identificazione e Preparazione dei BLOCCHI (Corsi e Certificati) ---

        # Processa erasmusInfo.learningAgreement.courses
        courses = student_data_full.get("erasmusInfo", {}).get("learningAgreement", {}).get("courses", [])
        for i, course_data in enumerate(courses):
            course_name = course_data.get("courseName", "Sconosciuto")
            # Usa indice basato su 0 per la corrispondenza con i percorsi interni
            block_path_prefix = f"erasmusInfo.learningAgreement.courses[{i}]"
            all_selectable_options.append({
                "type": "block",
                "display_title": f"Corso {i + 1}: {course_name}", # Visualizzazione 1-based per l'utente
                "data_path_prefix": block_path_prefix,
                "source_data": course_data
            })

        # Processa languageCertificates
        certs = student_data_full.get("erasmusInfo", {}).get("languageCertificates", [])
        for i, cert_data in enumerate(certs):
            cert_lang = cert_data.get("language", "Sconosciuta")
            cert_level = cert_data.get("level", "N/A")
            # Usa indice basato su 0 per la corrispondenza con i percorsi interni
            block_path_prefix = f"erasmusInfo.languageCertificates[{i}]"
            all_selectable_options.append({
                "type": "block",
                "display_title": f"Certificato {i + 1}: {cert_lang} ({cert_level})", # Visualizzazione 1-based per l'utente
                "data_path_prefix": block_path_prefix,
                "source_data": cert_data
            })

        # --- Identificazione e Preparazione degli ATTRIBUTI SINGOLI ---
        # Creiamo un set di tutti i prefissi dei blocchi per un controllo efficiente
        block_prefixes = {opt["data_path_prefix"] for opt in all_selectable_options if opt["type"] == "block"}

        # Identifica tutti i percorsi che fanno parte di un blocco completo
        paths_already_in_blocks = set()
        for bp in block_prefixes:
            for attr_path in all_flat_attributes.keys():
                if attr_path.startswith(bp):
                    paths_already_in_blocks.add(attr_path)

        for attr_path, attr_value in all_flat_attributes.items():
            # Assicurati di non includere attributi già parte di un blocco selezionabile
            # e di escludere le chiavi che rappresentano le liste stesse o dizionari annidati
            # che non sono foglie del Merkle Tree.
            if attr_path not in paths_already_in_blocks and \
               not isinstance(merkle_tree_for_paths._get_nested_value(student_data_full, attr_path), (dict, list)):
                all_selectable_options.append({
                    "type": "single",
                    "display_title": f"{attr_path}: {attr_value}",
                    "data_path": attr_path,
                    "source_data": attr_value
                })


        # Ordina per tipo (blocchi prima) e poi per display_title
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

                print(f"  [{display_index}] {option['display_title']}")

                if option["type"] == "block":
                    # Usa _flatten_dict di MerkleTree per coerenza nell'appiattimento per la visualizzazione dei dettagli
                    temp_flat_details = merkle_tree_for_paths._flatten_dict(option["source_data"])
                    for detail_key_raw in sorted(temp_flat_details.keys()):
                        # Rimuovi il prefisso del blocco per una visualizzazione più pulita dei dettagli
                        display_detail_key = detail_key_raw.replace(option["data_path_prefix"] + ".", "")
                        # Gestisci il caso in cui il blocco è un solo elemento con un suo path (es. languageCertificates[0])
                        if display_detail_key == "":
                            display_detail_key = "value" # O un'altra etichetta appropriata
                        print(f"    - {display_detail_key}: {temp_flat_details[detail_key_raw]}")
                    print("    " + "-" * 20)

                display_index += 1
        print("=" * 30)

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
                            paths_in_block = [p for p in all_flat_attributes.keys() if
                                              p.startswith(option["data_path_prefix"])]

                            for path in paths_in_block:
                                if path not in selected_by_user_paths:
                                    selected_by_user_paths.add(path)
                                    # Usa il valore da all_flat_attributes che ha i percorsi corretti
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
            # Ordina i percorsi per una visualizzazione coerente
            for attr_path in sorted(list(selected_by_user_paths)):
                print(f"  - {attr_path}: {all_flat_attributes.get(attr_path, 'N/A')}")
        print("=" * 70)

        return list(selected_by_user_paths)

    def create_verifiable_presentation(self, selected_attributes: List[str], issuer_public_key: Any) -> str:
        """Crea una Verifiable Presentation con divulgazione selettiva."""
        if not self.stored_vc:
            raise Exception("Nessuna VC conservata per creare la presentazione.")

        vc_jwt = self.stored_vc["vc_jwt"]
        student_data = self.stored_vc["student_data_full"]
        vc_payload = self.stored_vc["vc_payload"]

        print("\n🔍 CREAZIONE VERIFIABLE PRESENTATION")
        print("=" * 50)

        # Crea il Merkle Tree dai dati originali per generare le prove
        merkle_tree = EnhancedMerkleTree(student_data)
        # Assicurati che l'albero Merkle abbia l'original_data_for_proofs impostato
        merkle_tree.original_data_for_proofs = student_data

        # Genera le Merkle Proofs per gli attributi selezionati
        merkle_proofs = []
        disclosed_attributes = {}

        # Il Merkle Tree per la prova deve essere costruito con lo stesso metodo di appiattimento
        # usato per la selezione degli attributi.
        # all_flat_attributes qui deve essere generato dal metodo di EnhancedMerkleTree
        # per garantire che i percorsi siano coerenti con la logica Merkle.
        flat_student_data_for_merkle = merkle_tree._flatten_dict(student_data)

        for attribute_path in selected_attributes:
            proof = merkle_tree.calculate_merkle_proof(attribute_path)
            if proof:
                merkle_proofs.append(proof)
                # Recupera il valore usando il percorso dal dizionario appiattito del Merkle Tree
                disclosed_attributes[attribute_path] = flat_student_data_for_merkle.get(attribute_path)
            else:
                print(f"⚠️ Attributo '{attribute_path}' non trovato per la Merkle Proof.")

        # Genera nonce per anti-replay
        nonce = self.csprng.generate_nonce()

        # Crea la Verifiable Presentation
        now = datetime.now()
        vp_payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/presentations/v1"
            ],
            "id": f"https://erasmus.eu/presentations/{uuid.uuid4()}",
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": [{
                # Includi il JWT originale della VC per permettere la verifica della firma dell'emittente
                "originalCredentialJwt": vc_jwt,
                "proof": {
                    "type": "MerkleTreeProof2020",
                    "merkleProofs": merkle_proofs,
                    # Potremmo anche includere qui una copia degli attributi divulgati per chiarezza,
                    # anche se la verifica si basa sulle Merkle Proofs.
                    "disclosedAttributes": disclosed_attributes
                }
            }],
            "proof": {
                "type": "RsaSignature2018",
                "created": now.isoformat(),
                "proofPurpose": "authentication",
                "verificationMethod": f"{self.did}#key-1",
                "nonce": nonce
            }
        }

        # Firma la VP con la chiave dello studente
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        vp_jwt = jwt.encode(vp_payload, private_key_pem, algorithm="RS256")

        print(f"✅ Verifiable Presentation creata e firmata da {self.name}")
        print(f"📊 Attributi divulgati: {len(disclosed_attributes)}")
        print(f"🎯 Nonce: {nonce[:16]}...")

        return vp_jwt

    def demonstrate_credential_storage(self):
        """
        Dimostra il processo di conservazione e archiviazione delle credenziali
        come gestito da una DApp nel wallet dello studente.
        """
        if not self.stored_vc:
            print("⚠️ Nessuna Verifiable Credential da conservare.")
            return None

        credential_jwt = self.stored_vc["vc_jwt"]

        print("\n💾 PROCESSO DI CONSERVAZIONE CREDENZIALI")
        print("=" * 50)

        try:
            vc_payload = jwt.decode(credential_jwt, options={"verify_signature": False})
            credential_id = vc_payload["id"].split("/")[-1]
        except Exception as e:
            print(f"❌ ERRORE: Impossibile decodificare il JWT della credenziale per l'analisi: {e}")
            return None

        print("📋 Analisi della credenziale da conservare tramite DApp:")
        print(f"   🆔 ID: {credential_id}")
        print(f"   👤 Soggetto: {vc_payload['credentialSubject']['id']}")
        print(f"   🏛️  Emittente: {vc_payload['issuer']['name']}")
        print(f"   📅 Emessa il: {vc_payload['issuanceDate']}")
        print(f"   ⏰ Scade il: {vc_payload['expirationDate']}")
        print()

        print("🔄 La DApp avvia il processo di backup e archiviazione:")

        print("   📱 DApp: Creazione backup locale della credenziale...")
        time.sleep(0.5)
        print("   ✅ DApp: Backup locale completato")

        print("   ☁️  DApp: Sincronizzazione cloud (opzionale) in corso...")
        time.sleep(0.5)
        print("   ✅ DApp: Sincronizzazione cloud completata")

        print("   🔐 DApp: Crittografia del backup con chiave utente...")
        time.sleep(0.5)
        print("   ✅ DApp: Backup crittografato")

        print("   📊 DApp: Registrazione di metadati o hash su blockchain per tracciabilità...")
        time.sleep(0.5)
        print("   ✅ DApp: Transazione blockchain confermata")

        storage_metadata = {
            "credential_id": credential_id,
            "storage_date": datetime.now().isoformat(),
            "managed_by": "Student's DApp/Digital Wallet",
            "backup_locations": ["local_device_storage", "encrypted_cloud_storage", "blockchain_record"],
            "encryption_status": "AES-256 encrypted (at rest)",
            "integrity_check": "SHA-256 verified (on receipt)",
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

    def transmit_vp_to_verifier(self, vp_jwt: str, verifier_public_key: Any) -> Dict[str, bytes]:
        """Trasmissione sicura della VP con crittografia ibrida."""
        print("🔐 TRASMISSIONE VP CON CRITTOGRAFIA IBRIDA")
        print("=" * 50)

        vp_bytes = vp_jwt.encode('utf-8')
        encrypted_package = self.hybrid_crypto.encrypt_hybrid(
            vp_bytes, verifier_public_key
        )

        print("✅ Verifiable Presentation cifrata con AES-CTR")
        print("✅ Chiave di sessione cifrata con RSA-OAEP")
        print("📤 Pacchetto cifrato pronto per la trasmissione al verificatore")

        return encrypted_package