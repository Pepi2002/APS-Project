from DIDManager import EnhancedDIDManager
from RevocationRegistry import EnhancedRevocationRegistry
from HybridCrypto import HybridCrypto
from typing import Any, Optional, Dict
from MerkleTree import EnhancedMerkleTree
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import uuid
from datetime import datetime, timedelta
import jwt
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization

class Issuer:
    def __init__(self, did_manager: EnhancedDIDManager, revocation_registry: EnhancedRevocationRegistry, hybrid_crypto: HybridCrypto):
        self.did_manager = did_manager
        self.revocation_registry = revocation_registry
        self.hybrid_crypto = hybrid_crypto
        self.private_key: Any = None
        self.public_key: Any = None
        self.did: Optional[str] = None
        self.name: Optional[str] = None

    def generate_keys_and_did(self, name: str, entity_type: str = "university"):
        """Genera chiavi asimmetriche e DID per l'emittente."""
        print(f"🔑 Generazione chiavi e DID per l'Emittente: {name}...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.did = self.did_manager.create_did(name, entity_type, self.public_key)
        self.name = name
        print(f"✅ Chiavi generate e DID creato per {name}: {self.did}")

    def issue_verifiable_credential(self, student_did: str, student_data: Dict[str, Any]) -> str:
        """Emissione di Verifiable Credential con Merkle Tree."""
        print(f"\n🏛️  EMISSIONE VERIFIABLE CREDENTIAL da {self.name}")
        print("=" * 50)

        if not self.private_key or not self.did:
            raise Exception("Emittente non inizializzato: chiavi e DID mancanti.")

        student_info = student_data.get("studentInfo", {})
        print(f"📋 Studente: {student_info.get('name', 'N/A')} {student_info.get('surname', 'N/A')}")
        print(f"🎓 Corso: {student_info.get('degreeCourse', 'N/A')}")
        print(
            f"🏫 Università ospitante: {student_data.get('erasmusInfo', {}).get('hostUniversity', {}).get('name', 'N/A')}")
        print(
            f"📅 Periodo Erasmus: {student_data.get('erasmusInfo', {}).get('erasmusStartDate', 'N/A')} - {student_data.get('erasmusInfo', {}).get('erasmusEndDate', 'N/A')}")
        print()

        print("🌳 Creazione Merkle Tree per integrità dati...")
        merkle_tree = EnhancedMerkleTree(student_data)
        credential_id = str(uuid.uuid4())
        print(f"🆔 ID Credenziale generato: {credential_id}")
        print(f"🔗 Merkle Root calcolata: {merkle_tree.root[:32]}...")
        print()

        now = datetime.now()
        expiration_date = now + timedelta(days=365)

        print("📅 Informazioni temporali:")
        print(f"   📋 Data emissione: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   ⏰ Data scadenza: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        vc_payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://erasmus.eu/2024/credentials/v1"
            ],
            "id": f"https://erasmus.eu/credentials/{credential_id}",
            "type": ["VerifiableCredential", "ErasmusCredential"],
            "issuer": {
                "id": self.did,
                "name": self.name
            },
            "credentialSubject": {
                "id": student_did,
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
                "verificationMethod": f"{self.did}#key-1"
            }
        }

        print("✍️  Processo di firma digitale:")
        print(f"   🔑 Firmata con DID: {self.did}")
        print(f"   🏛️  Emittente: {self.name}")
        print(f"   📊 Algoritmo: RS256 (RSA-2048 + SHA-256)")

        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        credential_jwt = jwt.encode(vc_payload, private_key_pem, algorithm="RS256")

        print(f"   📋 Token JWT generato: {len(credential_jwt)} caratteri")
        print()

        print("✅ CREDENZIALE EMESSA CON SUCCESSO")
        print("─" * 40)
        print(f"📋 ID Credenziale: {credential_id[:16]}...")
        print(f"🌳 Merkle Root: {merkle_tree.root[:16]}...")
        print(f"🔒 Stato sicurezza: Firmata digitalmente")
        print(f"📊 Stato blockchain: Pronta per registrazione")
        print(f"⏰ Validità: {(expiration_date - now).days} giorni")
        return credential_jwt

    def transmit_vc_to_holder(self, vc_jwt: str, student_data_full: Dict[str, Any], holder_public_key: Any) -> Dict[
        str, bytes]:
        """
        Cifra la Verifiable Credential JWT e i dati completi dello studente
        utilizzando crittografia ibrida per la trasmissione sicura al Detentore (Studente).
        """
        print("\n🔐 TRASMISSIONE VC CON CRITTOGRAFIA IBRIDA (Emittente -> Detentore)")
        print("=" * 50)

        data_to_encrypt = {
            "vc_jwt": vc_jwt,
            "student_data_full": student_data_full
        }
        data_to_encrypt_json = json.dumps(data_to_encrypt)

        encrypted_package = self.hybrid_crypto.encrypt_hybrid(
            data_to_encrypt_json.encode('utf-8'), holder_public_key
        )

        print("✅ Verifiable Credential JWT e dati completi cifrati con AES-CTR")
        print("✅ Chiave di sessione cifrata con RSA-OAEP")
        print("📤 Pacchetto cifrato pronto per la trasmissione allo studente")
        return encrypted_package

    def revoke_credential(self, credential_jwt: str):
        """Revoca una credenziale emessa."""
        print("\n🚫 PROCESSO DI REVOCA")
        print("=" * 50)

        if not self.private_key or not self.did:
            raise Exception("Emittente non inizializzato: chiavi e DID mancanti.")

        vc_payload = jwt.decode(credential_jwt, options={"verify_signature": False})
        credential_id = vc_payload["id"].split("/")[-1]

        print(f"Revoca della credenziale ID: {credential_id[:16]}...")

        revocation_data = f"REVOKE:{credential_id}:{datetime.now().isoformat()}"
        signature = base64.b64encode(
            self.private_key.sign(
                revocation_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        ).decode()

        self.revocation_registry.revoke_credential(
            credential_id, self.did, signature, "Academic misconduct"
        )
        print(f"✅ Richiesta di revoca per {credential_id[:16]}... inviata al registro.")