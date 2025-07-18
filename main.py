from DIDManager import EnhancedDIDManager
from RevocationRegistry import EnhancedRevocationRegistry
from HybridCrypto import HybridCrypto
from NumberGenerator import CSPRNGGenerator
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from typing import Dict, Any, List
from MerkleTree import EnhancedMerkleTree
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
import jwt
import base64


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
        """Emissione di Verifiable Credential con Merkle Tree"""
        print("🏛️  EMISSIONE VERIFIABLE CREDENTIAL")
        print("=" * 50)

        # Crea il Merkle Tree dai dati dello studente
        merkle_tree = EnhancedMerkleTree(student_data)
        credential_id = str(uuid.uuid4())

        # Genera timestamp
        now = datetime.now()

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
            "expirationDate": (now + timedelta(days=365)).isoformat(),
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

        print(f"✅ Verifiable Credential emessa")
        print(f"📋 ID: {credential_id[:16]}...")
        print(f"🌳 Merkle Root: {merkle_tree.root[:16]}...")

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

    # 2. DIVULGAZIONE SELETTIVA E PRESENTAZIONE
    # Lo studente (Mario Rossi) crea una presentazione per l'università di origine (Salerno)
    # Sceglie di divulgare solo alcuni dati specifici (es. nome, cognome, voti)
    selected_attributes = [
        "studentInfo.name",
        "studentInfo.surname",
        "studentInfo.nationality",
        "erasmusInfo.learningAgreement.courses[0].courseName",
        "erasmusInfo.learningAgreement.courses[0].grade",
        "erasmusInfo.learningAgreement.courses[1].courseName",
        "erasmusInfo.learningAgreement.courses[1].grade",
        "erasmusInfo.learningAgreement.totalCredits"
    ]

    vp_jwt = system.create_verifiable_presentation(
        vc_jwt, student_data, selected_attributes
    )

    # 3. TRASMISSIONE SICURA
    # Lo studente cifra la presentazione con la chiave pubblica dell'università di origine
    # per garantire confidenzialità e integrità durante la trasmissione.
    encrypted_package = system.transmit_with_hybrid_encryption(vp_jwt)
    print("\n")

    # 4. VERIFICA DA PARTE DEL DESTINATARIO
    # L'università di origine (Salerno) riceve il pacchetto cifrato e lo verifica.
    # Questo processo include decifratura, verifica della firma dello studente,
    # controllo anti-replay, verifica delle Merkle Proofs e controllo dello stato di revoca.
    is_valid = system.verify_verifiable_presentation(encrypted_package)
    print(f"\nRisultato della prima verifica: {'VALIDA ✅' if is_valid else 'NON VALIDA ❌'}")
    print("\n")

    # 5. PROCESSO DI REVOCA
    # L'università emittente (Rennes) revoca la credenziale per una violazione.
    # La revoca viene registrata su una blockchain simulata.
    revoked_credential_id = system.demonstrate_revocation_process(vc_jwt)
    print(f"Credenziale ID '{revoked_credential_id[:16]}...' è stata revocata.")
    print("\n")

    # 6. SECONDO TENTATIVO DI VERIFICA
    # L'università di origine (Salerno) tenta di verificare nuovamente la stessa presentazione.
    # Questa volta, la verifica fallirà perché la credenziale è ora sulla lista di revoca.
    print("🔄 Tentativo di riverificare la stessa presentazione dopo la revoca...")
    is_still_valid = system.verify_verifiable_presentation(encrypted_package)
    print(f"\nRisultato della seconda verifica (post-revoca): {'VALIDA ✅' if is_still_valid else 'NON VALIDA ❌'}")
    print("\n")

    print("=" * 60)
    print("🏁 Dimostrazione completata.")
    print("=" * 60)


if __name__ == "__main__":
    main()