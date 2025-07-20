from typing import Dict, Any

import jwt

from ActorsPepi.AccreditationAuthority import AccreditationAuthority
from ActorsPepi.Actor import Actor
from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry


class Verifier(Actor):
    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)
        self.nonce_registry = set()

    def check_nonce(self, nonce: str) -> bool:
        if nonce in self.nonce_registry:
            print(f"Nonce {nonce} già usato, possibile replay attack.")
            return False
        self.nonce_registry.add(nonce)
        return True

    def verify_holder_signature(self, vp_payload: Dict[str, Any], holder_public_key_pem: bytes) -> bool:
        """
        Verifica la firma dello studente usando la chiave pubblica in PEM.
        """
        raise NotImplementedError("verify_holder_signature deve essere implementato.")

    def verify_issuer_signature(self, credential_jwt: str, issuer_public_key_pem: bytes) -> bool:
        """
        Verifica la firma della credenziale emessa dall’issuer originale.
        """
        raise NotImplementedError("verify_issuer_signature deve essere implementato.")

    def verify_merkle_root(self, disclosed_attributes: dict, merkle_proofs: list, expected_merkle_root: str) -> bool:
        """
        Ricostruisce la Merkle root a partire dagli attributi divulgati e proof,
        e la confronta con quella attesa.
        """
        raise NotImplementedError("Verifica Merkle root da implementare.")

    def is_revoked(self, credential_id: str) -> bool:
        """
        Controlla se la credenziale è stata revocata consultando la blockchain.
        """
        raise NotImplementedError("Verifica revoca da implementare.")

    @staticmethod
    def obtain_structured_data(jwt_token: str, public_key_pem: bytes) -> dict:
        try:
            # decodifica e verifica firma
            data = jwt.decode(jwt_token, public_key_pem, algorithms=["RS256"])
            return data
        except jwt.ExpiredSignatureError:
            print("Token scaduto")
            return None
        except jwt.InvalidSignatureError:
            print("Firma non valida")
            return None
        except Exception as e:
            print(f"Errore nel decoding JWT: {e}")
            return None

    def verify_presentation(
            self,
            encrypted_package: bytes,
            holder_public_key_pem: bytes,
            issuer_public_key_pem: bytes,
            accreditation_authority: AccreditationAuthority
    ) -> bool:
        """
        Metodo principale per la verifica completa di una Verifiable Presentation (VP).
        """
        try:
            # 1. Decifrare il pacchetto di presentazione
            vp = self.decrypt_presentation(encrypted_package)

            # Controllo accredito Issuer
            issuer_did = vp.get("iss")
            if issuer_did is None:
                print("Issuer DID mancante nella presentazione.")
                return False

            if not accreditation_authority.is_did_accredited(issuer_did):
                print(f"Issuer {issuer_did} non è accreditato.")
                return False

            # 2. Verificare nonce
            nonce = vp.get("nonce")
            if not nonce or not self.check_nonce(nonce):
                print("Nonce non valido o già usato.")
                return False

            # 3. Verifica firma dello studente (holder)
            if not self.verify_holder_signature(vp, holder_public_key_pem):
                print("Firma dello studente non valida.")
                return False

            # 4. Verifica firma dell'issuer originale (sulla credenziale JWT)
            credential_jwt = vp.get("credential_jwt")
            if not credential_jwt:
                print("Credenziale JWT mancante nella presentazione.")
                return False

            if not self.verify_issuer_signature(credential_jwt, issuer_public_key_pem):
                print("Firma dell'issuer non valida.")
                return False

            # 5. Verifica Merkle root
            disclosed_attributes = vp.get("disclosed_attributes")
            merkle_proofs = vp.get("merkle_proofs")
            expected_merkle_root = vp.get("expected_merkle_root")

            if not self.verify_merkle_root(disclosed_attributes, merkle_proofs, expected_merkle_root):
                print("Verifica Merkle root fallita.")
                return False

            # 6. Controllo stato revoca
            credential_id = vp.get("credential_id")
            if credential_id and self.is_revoked(credential_id):
                print("Credenziale revocata.")
                return False

            # Tutte le verifiche sono andate a buon fine
            return True

        except Exception as e:
            print(f"Errore durante la verifica della presentazione: {e}")
            return False



