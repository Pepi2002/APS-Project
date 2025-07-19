import base64
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any

import jwt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from OtherTechnologies.MerkleTree import EnhancedMerkleTree
from OtherTechnologies.HybridCrypto import HybridCrypto
from PepiAPS1 import AccreditationAuthority


class Issuer:
    def __init__(self):
        self.public_key, self.private_key = self.generate_keys
        self.hybrid_crypto = HybridCrypto()

    @staticmethod
    def generate_keys():
        print("🔑 Generazione chiavi asimmetriche con CSPRNG...")

        # Genera chiavi per l'Università Ospitante
        issuer_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        issuer_public_key = issuer_private_key.public_key()

        return issuer_public_key, issuer_private_key

    def request_accreditation(self, accreditation_authority: AccreditationAuthority, did: str):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        request_payload = {
            "did": did,
            "public_key": public_key_pem,
            "timestamp": datetime.now().isoformat()
        }

        payload_json = json.dumps(request_payload)

        signature = base64.b64encode(
            self.private_key.sign(
                payload_json.encode(),
                padding.PSS(
                    mgf = padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size
                ),
                hashes.SHA256()
            )
        ).decode()

        request_message = {
            "payload" : request_payload,
            "signature": signature
        }

        certificate = accreditation_authority.process_accreditation_request(request_message)
        return certificate

    @staticmethod
    def create_detailed_student_data() -> Dict[str, Any]:
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
                    "did": "self.home_did"
                }
            },
            "erasmusInfo": {
                "hostUniversity": {
                    "name": "Université de Rennes",
                    "code": "UR1",
                    "country": "France",
                    "did": "self.host_did"
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

    def create_verifiable_credential(self) -> str:
        print("🏛️  CREAZIONE VERIFIABLE CREDENTIAL")
        print("=" * 50)

        student_data = self.create_detailed_student_data()

        merkle_tree = EnhancedMerkleTree(student_data)
        credential_id = str(uuid.uuid4())

        now = datetime.now()
        expiration_date = now + timedelta(days=365)

        vc_payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://erasmus.eu/2024/credentials/v1"
            ],
            "id": f"https://erasmus.eu/credentials/{credential_id}",
            "type": ["VerifiableCredential", "ErasmusCredential"],
            "issuer": {
                "id": "self.host_did",
                "name": "Université de Rennes"
            },
            "credentialSubject": {
                "id": "self.student_did",
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
                "verificationMethod": f"self.host_did#key-1"
            }
        }

        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        credential_jwt = jwt.encode(
            vc_payload,
            private_key_pem,
            algorithm="RS256"
        )
        return credential_jwt

    def transmit_vc(self, vc_jwt: str, student_data_full: Dict[str, Any]) -> Dict[str, str]:
        print("\n🔐 TRASMISSIONE VC CON CRITTOGRAFIA IBRIDA")
        print("=" * 50)

        data_to_encrypt = {
            "vc_jwt": vc_jwt,
            "student_data_full": student_data_full
        }

        data_to_encrypt_json = json.dumps(data_to_encrypt)

        encrypted_package = self.hybrid_crypto.encrypt_hybrid(
            data_to_encrypt_json.encode('utf-8'), self.public_key
        )

        return encrypted_package

