import uuid
import datetime
from typing import Dict, Any

import jwt


class CredentialUtils:
    """Classe Utils per la creazione di credenziali"""

    @staticmethod
    def load_mock_student_data() -> Dict:
        """Mock di dati accademici dettagliati dello studente (non firmati)"""
        return {
            "studentInfo": {
                "name": "Mario",
                "surname": "Rossi",
                "studentId": "123456",
                "birthdate": "1999-04-15",
                "nationality": "Italian",
                "email": "mario.rossi@student.univ.it",
                "degreeCourse": "Ingegneria Informatica",
                "courseDuration": "3 years",
                "homeUniversity": {
                    "name": "Università di Roma",
                    "code": "UNIRM",
                    "country": "IT"
                }
            },
            "erasmusInfo": {
                "hostUniversity": {
                    "name": "Universidad de Sevilla",
                    "code": "USEV",
                    "country": "ES"
                },
                "erasmusStartDate": "2023-09-01",
                "erasmusEndDate": "2024-02-28",
                "learningAgreement": {
                    "period": "1st semester",
                    "agreedCourses": [
                        {
                            "courseName": "Data Structures",
                            "courseCode": "INF102",
                            "ects": 6,
                            "status": "passed",
                            "grade": 28,
                            "honor": False,
                            "completionDate": "2024-01-10"
                        }
                    ],
                    "agreedCredits": 30,
                    "completedCredits": 30
                },
                "languageCertificates": [
                    {
                        "language": "English",
                        "level": "B2",
                        "certification": "IELTS",
                        "certificationScore": 6.5
                    }
                ],
                "otherActivities": [
                    {
                        "title": "Machine Learning Workshop",
                        "provider": "Host University",
                        "hours": 12,
                        "completionDate": "2023-12-15"
                    }
                ]
            }
        }

    @staticmethod
    def generate_verifiable_credential(
            issuer_did: str,
            holder_did: str,
            accreditation_did: str,
            private_key: str,
            merkle_root: str,
            exp_days: int = 365
    ) -> str:
        """
        Genera una Credenziale Accademica Verificabile (VC) firmata con RS256.

        :param accreditation_did:
        :param issuer_did: DID dell'università emittente (issuer)
        :param holder_did: DID del titolare della credenziale (studente)
        :param private_key: chiave privata dell'emittente per firmare il JWT
        :param merkle_root: Merkle root calcolata sui dati accademici dettagliati
        :param exp_days: giorni di validità della credenziale
        :return: JWT (Verifiable Credential)
        """

        #Ottiene la data attuale
        now = datetime.datetime.now(datetime.timezone.utc)

        #Crea un identificativo univoco
        credential_id = str(uuid.uuid4())

        #Crea il payload della credenziale
        payload = {
            "jti": credential_id,
            "iss": issuer_did,
            "sub": holder_did,
            "acc": accreditation_did,
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(days=exp_days)).timestamp()),
            "type": "ErasmusCredential",
            "credentialStatus": {
                "id": f"https://blockchain.erasmus.eu/revocation/{credential_id}",
                "type": "RevocationList2025"
            },
            "merkleRoot": merkle_root
        }

        #Crea l'header della credenziale
        headers = {
            "alg": "RS256",
            "typ": "JWT"
        }

        #Ritorna la credenziale firmata usando la chiave privata di chi l'ha creata
        return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

    @staticmethod
    def generate_verifiable_presentation(
            holder_did: str,
            verifier_did: str,
            private_key: str,
            verified_vc_jwt: str,
            disclosed_data: Dict,
            merkle_proofs: dict[str, list[tuple[str, str]]],
            nonce: str,
            exp_minutes: int = 30
    ) -> str:
        """
        Genera una Presentazione Accademica Verificabile (VP), partendo da una VC già verificata.

        :param verified_vc_jwt:
        :param holder_did: DID dello studente
        :param verifier_did: DID del verificatore (destinatario)
        :param private_key: chiave privata dello studente per firmare la VP
        :param disclosed_data: sottoinsieme dei dati accademici da divulgare
        :param merkle_proofs: le Merkle Proofs associate ai dati divulgati
        :param nonce: nonce fornito dal verificatore per evitare replay attack
        :param exp_minutes: tempo di validità della VP
        :return: JWT firmato (VP)
        """

        #Ottiene la data attuale
        now = datetime.datetime.now(datetime.timezone.utc)

        #Crea payload della credenziale
        payload = {
            "jti": str(uuid.uuid4()), #Crea identificativo Uunivoco
            "iss": holder_did,
            "aud": verifier_did,
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(minutes=exp_minutes)).timestamp()),
            "nonce": nonce,
            "verifiableCredential": verified_vc_jwt,
            "studentData": disclosed_data,
            "merkleProofs": merkle_proofs
        }

        #Crea header della credenziale
        headers = {
            "alg": "RS256",
            "typ": "JWT"
        }

        #Ritorna la credenziale firmata con la chiave privata di chi l'ha creata
        return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)