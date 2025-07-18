from DIDManager import EnhancedDIDManager
from RevocationRegistry import EnhancedRevocationRegistry
from HybridCrypto import HybridCrypto
from NumberGenerator import CSPRNGGenerator
from typing import Dict, Any
from Issuer import Issuer
from Verifier import Verifier
from Holder import Holder


class ErasmusSystemOrchestrator:
    """Orchestra il flusso di emissione, ricezione e verifica delle credenziali Erasmus."""

    def __init__(self):
        self.did_manager = EnhancedDIDManager()
        self.revocation_registry = EnhancedRevocationRegistry()
        self.hybrid_crypto = HybridCrypto()
        self.csprng = CSPRNGGenerator()

        self.host_university = Issuer(self.did_manager, self.revocation_registry, self.hybrid_crypto)
        self.home_university = Verifier(self.did_manager, self.hybrid_crypto, self.revocation_registry)
        self.student = Holder(self.did_manager, self.hybrid_crypto, self.csprng)

    def setup_entities(self):
        print("\n--- INIZIALIZZAZIONE DEL SISTEMA ERASMUS ---")
        self.host_university.generate_keys_and_did("Université de Rennes")
        self.home_university.generate_keys_and_did("Università di Salerno")
        self.student.generate_keys_and_did("Mario Rossi")
        print("-------------------------------------------\n")

    def create_detailed_student_data(self) -> Dict[str, Any]:
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
                    "did": self.home_university.did
                }
            },
            "erasmusInfo": {
                "hostUniversity": {
                    "name": "Université de Rennes",
                    "code": "UR1",
                    "country": "France",
                    "did": self.host_university.did
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

    def simulate_full_flow(self):
        print("\n=== INIZIO SIMULAZIONE COMPLETA DEL SISTEMA ERASMUS ===")

        self.setup_entities()

        student_data_full = self.create_detailed_student_data()

        print("\n--- FASE 1: EMISSIONE DELLA VERIFIABLE CREDENTIAL ---")
        vc_jwt = self.host_university.issue_verifiable_credential(self.student.did, student_data_full)
        if not vc_jwt:
            print("Simulazione interrotta: Emissione VC fallita.")
            return

        # MODIFICA: Chiamata corretta al metodo transmit_vc_to_holder
        print("\n--- FASE 2: TRASMISSIONE SICURA VC DALL'EMITTENTE ALLO STUDENTE ---")
        encrypted_vc_package = self.host_university.transmit_vc_to_holder(vc_jwt, student_data_full, self.student.public_key)
        if not encrypted_vc_package:
            print("Simulazione interrotta: Trasmissione VC cifrata fallita.")
            return

        print("\n--- FASE 3: RICEZIONE E VERIFICA VC DA PARTE DELLO STUDENTE ---")
        vc_verified = self.student.receive_and_verify_vc(
            encrypted_vc_package,
            self.host_university.public_key,
            self.revocation_registry
        )
        if not vc_verified:
            print("Simulazione interrotta: Verifica VC da parte dello studente fallita.")
            return

        print("\n--- FASE 4: CONSERVAZIONE NEL WALLET DELLO STUDENTE ---")
        self.student.demonstrate_credential_storage()

        print("\n--- FASE 5: CREAZIONE VERIFIABLE PRESENTATION ---")
        selected_attributes = self.student.select_attributes_for_vp()
        if not selected_attributes:
            print("Simulazione interrotta: Nessun attributo selezionato per la VP.")
            return

        vp_jwt = self.student.create_verifiable_presentation(
            selected_attributes, self.host_university.public_key
        )
        if not vp_jwt:
            print("Simulazione interrotta: Creazione VP fallita.")
            return

        print("\n--- FASE 6: TRASMISSIONE SICURA VP ALL'UNIVERSITÀ DI ORIGINE ---")
        encrypted_vp_package = self.student.transmit_vp_to_verifier(
            vp_jwt, self.home_university.public_key
        )
        if not encrypted_vp_package:
            print("Simulazione interrotta: Trasmissione VP cifrata fallita.")
            return

        print("\n--- FASE 7: VERIFICA VP DA PARTE DELL'UNIVERSITÀ DI ORIGINE ---")
        vp_is_valid = self.home_university.verify_verifiable_presentation(encrypted_vp_package)
        if vp_is_valid:
            print("\n🎉 SIMULAZIONE COMPLETATA CON SUCCESSO! 🎉")
        else:
            print("\n❌ SIMULAZIONE FALLITA: La Verifiable Presentation non è stata verificata.")

if __name__ == "__main__":
    orchestrator = ErasmusSystemOrchestrator()
    orchestrator.simulate_full_flow()