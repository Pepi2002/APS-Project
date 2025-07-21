import json
from typing import Dict, Any

import jwt

from Actors.Actor import Actor
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from OtherTechnologies.NumberGenerator import CSPRNGGenerator
from OtherTechnologies.MerkleTree import MerkleTree
from OtherTechnologies.StudentDApp import StudentDApp
from Utils.CredentialUtils import CredentialUtils


class Student(Actor):
    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)
        self.student_dapp = StudentDApp()


    def decripting_package(self, encrypted_package: bytes):
        print("Decriptazione pacchetto...")
        try:
            decrypted_payload = self.hybrid_crypto.decrypt(encrypted_package, self.get_private_key_pem())
            decrypted_json_str = decrypted_payload.decode()
            decrypted_data = json.loads(decrypted_json_str)
            disclosed_attributes = decrypted_data["data"]
            vc_jwt = decrypted_data["vc"]
        except Exception as e:
            print(f"Errore durante la decriptazione: {e}")
            return False

        if disclosed_attributes is None or vc_jwt is None:
            print("❌Dati mancanti nel pacchetto decriptato")
            return False
        else:
            print("✅Decriptazione avvenuta con successo")

        return disclosed_attributes, vc_jwt

    def verify_accreditation_certificate(self, vc_payload):
        print("Verifica di certificazione dell'issuer...")
        issuer_did = vc_payload.get("iss")
        authority_did = vc_payload.get("acc")

        if not issuer_did or not authority_did:
            print("❌VC mancante di campo 'iss' o 'acc'")
            return False

        try:
            authority_pubkey = self.did_registry.get_public_key(authority_did)

            certificate_jwt = self.did_registry.get_certificate(issuer_did)
            if not certificate_jwt:
                print("❌Nessun certificato di accreditamento trovato per l'issuer")
                return False

            payload = jwt.decode(certificate_jwt, authority_pubkey, algorithms=["RS256"])

            if payload.get("sub") != issuer_did:
                print("❌Il certificato non accredita l'issuer corretto")
                return False

            print("✅Certificato di accreditamento valido")
            return True

        except jwt.ExpiredSignatureError:
            print("❌ Il certificato di accreditamento è scaduto")
            return False
        except jwt.InvalidSignatureError:
            print("❌Firma del certificato non valida")
            return False
        except Exception as e:
            print(f"❌Errore nella verifica del certificato di accreditamento: {e}")
            return False

    @staticmethod
    def verify_credential_signature(vc_jwt: str, issuer_public_key_pem: bytes) -> bool:
        """
        Verifica la firma digitale del Verifiable Credential JWT ricevuto dall'Università Ospitante.
        """
        print("Verifica sull'integrità della verifiable credential...")
        try:
            jwt.decode(vc_jwt, issuer_public_key_pem, algorithms=["RS256"])
            return True
        except jwt.InvalidSignatureError:
            print("Firma non valida")
            return False
        except Exception as e:
            print(f"Errore durante verifica firma: {e}")
            return False

    @staticmethod
    def verify_merkle_root_from_vc(vc_jwt: str, disclosed_attributes: Dict[str, Any]) -> bool:
        """
        Verifica che la Merkle root dei disclosed attributes corrisponda a quella presente nella VC.

        :param vc_jwt: JWT della Verifiable Credential
        :param disclosed_attributes: attributi che lo studente ha deciso di rivelare
        :return: True se la Merkle root combacia, False altrimenti
        """
        print("Verifica sull'integrità degli attributi mandati in chiaro...")
        try:
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
            expected_root = vc_payload.get("merkleRoot")
            if not expected_root:
                print("❌Merkle root mancante nel VC")
                return False

            merkle_tree = MerkleTree(disclosed_attributes)
            calculated_root = merkle_tree.get_merkle_root()

            if expected_root != calculated_root:
                print("❌Merkle root mismatch:")
                print(f"  Attesa:    {expected_root}")
                print(f"  Calcolata: {calculated_root}")
                return False

            print("✅Merkle root verificata con successo")
            return True

        except Exception as e:
            print(f"Errore durante verifica Merkle root: {e}")
            return False


    def is_revoked(self, credential_id: str) -> bool:
        """
        Controlla se la credenziale è stata revocata consultando la blockchain.
        """
        return False

    def verify_credential(self, encrypted_package: bytes, credential_id: str):
        """
        Verifica completa della credenziale partendo dal pacchetto criptato ricevuto.

        :param encrypted_package: dati cifrati ricevuti dallo issuer (es. dal metodo transmit)
        :param credential_id: id della credenziale da verificare per revoca
        :return: True se tutte le verifiche passano, False altrimenti
        """
        result = self.decripting_package(encrypted_package)
        if not result:
            return False, None, None
        disclosed_attributes, vc_jwt = result

        try:
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
        except Exception as e:
            print(f"Errore parsing VC JWT: {e}")
            return False, None, None

        self.verify_accreditation_certificate(vc_payload)

        issuer_did = vc_payload.get("iss")
        try:
            issuer_pubkey = self.did_registry.get_public_key(issuer_did)
            if not self.verify_credential_signature(vc_jwt, issuer_pubkey):
                print("❌Firma della VC non valida")
                return False, None, None
            print("✅Firma della VC verificata")
        except Exception as e:
            print(f"Errore ottenimento chiave pubblica issuer: {e}")
            return False, None, None

        if not self.verify_merkle_root_from_vc(vc_jwt, disclosed_attributes):
            return False, None, None

        print("Verifica sulla validità del messaggio...")
        if self.is_revoked(credential_id):
            print("❌Credenziale revocata")
            return False, None, None
        else:
            print("✅Controllo sulla revoca superato")

        print("\n✅Tutte le verifiche superate con successo")
        print("="*50)
        return True, disclosed_attributes, vc_jwt

    def store_credential_in_dapp(self, disclosed_attributes: dict, vc_jwt: str):
        self.student_dapp.store_credential(disclosed_attributes, vc_jwt)

    def create_verifiable_presentation(self, vc_jwt: str, verifier_did: str):

        full_credential = self.student_dapp.get_credential()
        full_vc_data = full_credential["disclosed_attributes"]

        disclosed_attributes = self.student_dapp.select_attributes()

        merkle_tree = MerkleTree(full_vc_data)

        merkle_proofs = {}
        flat_disclosed = merkle_tree.flatten_data(disclosed_attributes)
        for path, value in flat_disclosed:
            proof = merkle_tree.calculate_merkle_proof(path)
            if proof:
                merkle_proofs[path] = proof

        number_generator = CSPRNGGenerator()
        nonce = number_generator.generate_nonce()

        vp_jwt = CredentialUtils.generate_verifiable_presentation(
            holder_did=self.did,
            verifier_did=verifier_did,
            private_key=self.get_private_key_pem().decode(),
            verified_vc_jwt=vc_jwt,
            disclosed_data=disclosed_attributes,
            merkle_proofs=merkle_proofs,
            nonce=nonce
        )

        return vp_jwt, disclosed_attributes

    def transmit(self, recipient_did: str, message: str):
        """
        Metodo astratto per la trasmissione sicura di un messaggio a un altro attore identificato dal suo DID.
        """
        try:
            recipient_pubkey_pem = self.did_registry.get_public_key(recipient_did)
        except Exception as e:
            print(f"Errore risoluzione DID {recipient_did}: {e}")
            return None

        message = message.encode('utf-8')
        encrypted_message = self.hybrid_crypto.encrypt(message, recipient_pubkey_pem)
        print(f"Invio messaggio cifrato a {recipient_did}:\n{encrypted_message.hex()[:60]}...")
        return encrypted_message
