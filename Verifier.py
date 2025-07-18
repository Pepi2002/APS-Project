from DIDManager import EnhancedDIDManager
from HybridCrypto import HybridCrypto
from RevocationRegistry import EnhancedRevocationRegistry
from typing import Any, Optional, Set, Dict
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from MerkleTree import EnhancedMerkleTree


class Verifier:
    def __init__(self, did_manager: EnhancedDIDManager, hybrid_crypto: HybridCrypto,
                 revocation_registry: EnhancedRevocationRegistry):
        self.did_manager = did_manager
        self.hybrid_crypto = hybrid_crypto
        self.revocation_registry = revocation_registry
        self.private_key: Any = None
        self.public_key: Any = None
        self.did: Optional[str] = None
        self.name: Optional[str] = None
        self.used_nonces: Set[str] = set()  # Nonces per anti-replay nelle VP

    def generate_keys_and_did(self, name: str, entity_type: str = "university"):
        """Genera chiavi asimmetriche e DID per il verificatore."""
        print(f"🔑 Generazione chiavi e DID per il Verificatore: {name}...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.did = self.did_manager.create_did(name, entity_type, self.public_key)
        self.name = name
        print(f"✅ Chiavi generate e DID creato per {name}: {self.did}")

    def verify_verifiable_presentation(self, encrypted_package: Dict[str, bytes]) -> bool:
        """Verifica completa della Verifiable Presentation."""
        print(f"\n🕵️  VERIFICA VERIFIABLE PRESENTATION da {self.name}")
        print("=" * 50)

        if not self.private_key:
            raise Exception("Verificatore non inizializzato: chiave privata mancante.")

        try:
            # Fase 1: Decifratura ibrida
            print("1. 🔓 Decifratura del pacchetto ricevuto...")
            decrypted_vp_jwt = self.hybrid_crypto.decrypt_hybrid(
                encrypted_package, self.private_key
            ).decode('utf-8')

            # Fase 2: Verifica firma dello studente e anti-replay sulla VP
            print("2. ✍️  Verifica della firma del detentore e del nonce...")
            vp_payload = jwt.decode(decrypted_vp_jwt, options={
                "verify_signature": False})  # Decodifica iniziale senza verifica per ottenere DID holder

            holder_did = vp_payload.get("holder")
            if not holder_did:
                print("❌ ERRORE: DID del detentore non trovato nella VP.")
                return False

            holder_public_key = self.did_manager.get_public_key(holder_did)
            if not holder_public_key:
                print(f"❌ ERRORE: Chiave pubblica del detentore ({holder_did}) non trovata nel DID Manager.")
                return False

            holder_public_key_pem = holder_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Ora decodifica con verifica della firma
            vp_payload = jwt.decode(decrypted_vp_jwt, holder_public_key_pem, algorithms=["RS256"])

            nonce = vp_payload["proof"]["nonce"]
            if nonce in self.used_nonces:
                print("❌ ERRORE: Nonce già utilizzato (possibile replay attack).")
                return False
            # Aggiungi il nonce a quelli usati SOLO se la verifica prosegue con successo, alla fine.

            print("✅ Firma del detentore verificata")
            print("✅ Verifica anti-replay completata")

            # Fase 3: Estrazione della VC originale e verifica della firma dell'emittente
            print("3. 🏛️  Verifica della credenziale originale dell'emittente...")
            vc_info_in_vp = vp_payload["verifiableCredential"][0]
            vc_jwt = vc_info_in_vp["originalCredentialJwt"]

            # Decodifica iniziale della VC per ottenere l'ID dell'emittente
            vc_original_payload_decoded = jwt.decode(vc_jwt, options={"verify_signature": False})
            issuer_did_from_vc = vc_original_payload_decoded.get("issuer", {}).get("id")

            if not issuer_did_from_vc:
                print("❌ ERRORE: DID dell'emittente non trovato nella VC originale.")
                return False

            issuer_public_key = self.did_manager.get_public_key(issuer_did_from_vc)
            if not issuer_public_key:
                print(f"❌ ERRORE: Chiave pubblica dell'emittente ({issuer_did_from_vc}) non trovata nel DID Manager.")
                return False

            issuer_public_key_pem = issuer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Verifica la firma della VC originale
            vc_payload_verified = jwt.decode(vc_jwt, issuer_public_key_pem, algorithms=["RS256"])
            print("✅ Firma dell'emittente (Università Ospitante) verificata")

            # Fase 4: Verifica stato di revoca (usando l'ID della VC originale)
            print("4. 📜 Verifica dello stato di revoca della VC...")
            credential_id = vc_payload_verified["id"].split("/")[-1]
            if self.revocation_registry.is_revoked(credential_id):
                print(f"❌ ERRORE: La credenziale {credential_id[:16]}... risulta revocata!")
                return False
            print("✅ Credenziale non revocata")

            # Fase 5: Verifica delle Merkle Proofs e ricostruzione degli attributi divulgati
            print("5. 🌳 Verifica delle Merkle Proofs e dati divulgati...")
            merkle_proofs = vc_info_in_vp["proof"]["merkleProofs"]
            merkle_root_from_vc = vc_payload_verified["credentialSubject"]["merkleRoot"]
            disclosed_attributes = vc_info_in_vp["proof"].get("disclosedAttributes", {})  # Recupera attributi divulgati

            # Per la verifica delle Merkle Proofs, dobbiamo ricostruire l'albero con la root originale
            # e poi verificare ogni prova.
            temp_tree = EnhancedMerkleTree({})  # Inizializza con dati vuoti
            temp_tree.root = merkle_root_from_vc  # Imposta la root dal VC per la verifica

            # Qui la logica del verify_merkle_proof è fondamentale.
            # Dobbiamo simulare che la proof contenga l'hash dell'attributo e il percorso per risalire alla root.
            # La nostra `verify_merkle_proof` è semplificata. Dobbiamo assicuraci che funzioni.

            all_proofs_valid = True
            for proof in merkle_proofs:
                # Per una Merkle proof completa, avremmo bisogno di re-hashare il leaf_hash con gli hash dei fratelli
                # per ricostruire la root. Data la semplificazione di EnhancedMerkleTree,
                # ci basiamo sul fatto che il 'leaf_hash' e la 'merkle_root' sono forniti nella proof stessa.
                # In un sistema reale, `verify_merkle_proof` sarebbe più complessa.

                # Per questa simulazione, verifichiamo che la leaf_hash corrisponda
                # all'hash ricalcolato dell'attributo divulgato e che la root della proof corrisponda alla root del VC.
                attr_path_in_proof = proof["attribute_path"]
                leaf_hash_in_proof = proof["leaf_hash"]
                root_in_proof = proof["merkle_root"]

                # Ricalcola l'hash dell'attributo divulgato usando i dati forniti nella VP
                # (assumiamo che 'disclosedAttributes' contenga i valori esatti)
                disclosed_value = disclosed_attributes.get(attr_path_in_proof)
                if disclosed_value is None:
                    print(
                        f"❌ ERRORE: Valore per l'attributo '{attr_path_in_proof}' non trovato tra gli attributi divulgati.")
                    all_proofs_valid = False
                    break

                recalculated_leaf_hash = temp_tree._hash_data(f"{attr_path_in_proof}:{disclosed_value}")

                if recalculated_leaf_hash != leaf_hash_in_proof:
                    print(f"❌ ERRORE: Hash della foglia non corrispondente per '{attr_path_in_proof}'.")
                    all_proofs_valid = False
                    break

                if root_in_proof != merkle_root_from_vc:
                    print(
                        f"❌ ERRORE: Merkle Root nella prova non corrispondente alla root nel VC per '{attr_path_in_proof}'.")
                    all_proofs_valid = False
                    break

            if not all_proofs_valid:
                print("❌ ERRORE: Una o più Merkle Proofs o attributi divulgati non sono validi.")
                return False
            print("✅ Tutte le Merkle Proofs sono state verificate con successo")

            # Se tutto è andato a buon fine, aggiungi il nonce a quelli usati
            self.used_nonces.add(nonce)

            print("\n🎉 VERIFICA COMPLETA DELLA VERIFIABLE PRESENTATION RIUSCITA!")
            print(f"Attributi divulgati e verificati per {holder_did}:")
            for attr_path, attr_value in disclosed_attributes.items():
                print(f"  - {attr_path}: {attr_value}")
            return True

        except jwt.exceptions.InvalidSignatureError as e:
            print(f"❌ ERRORE DI FIRMA nella VP: {str(e)}")
            return False
        except jwt.exceptions.ExpiredSignatureError as e:
            print(f"❌ ERRORE: VP Token scaduto: {str(e)}")
            return False
        except jwt.exceptions.DecodeError as e:
            print(f"❌ ERRORE: VP Token malformato o errore di decifratura: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ ERRORE IMPREVISTO nella verifica VP: {str(e)}")
            return False