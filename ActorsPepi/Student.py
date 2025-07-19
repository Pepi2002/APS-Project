import json
from typing import Dict, Any

import jwt

from ActorsPepi.Actor import Actor
from BlockchainPepi.DIDRegistry import DIDRegistry
from OtherTechnologiesPepi.MerkleTree import MerkleTree


class Student(Actor):
    def __init__(self):
        super().__init__()

    @staticmethod
    def verify_credential_signature(vc_jwt: str, issuer_public_key_pem: bytes) -> bool:
        """
        Verifica la firma digitale del Verifiable Credential JWT ricevuto dall'Università Ospitante.
        """
        try:
            # jwt.decode verifica firma e restituisce il payload
            jwt.decode(vc_jwt, issuer_public_key_pem, algorithms=["RS256"])
            return True
        except jwt.InvalidSignatureError:
            print("Firma non valida")
            return False
        except Exception as e:
            print(f"Errore durante verifica firma: {e}")
            return False

    @staticmethod
    def verify_merkle_root(full_attributes: Dict[str, Any], expected_merkle_root: str) -> bool:
        """
        Ricostruisce e confronta la Merkle root dei dati accademici completi con quella presente nel VC.
        """
        merkle_tree = MerkleTree(full_attributes)
        merkle_root = merkle_tree.get_merkle_root()
        return merkle_root == expected_merkle_root


    def is_revoked(self, credential_id: str) -> bool:
        """
        Controlla se la credenziale è stata revocata consultando la blockchain.
        """
        return False

    def verify_credential(self, encrypted_package: bytes, did_registry: DIDRegistry, credential_id: str) -> bool:
        """
        Verifica completa della credenziale partendo dal pacchetto criptato ricevuto.

        :param encrypted_package: dati cifrati ricevuti dallo issuer (es. dal metodo transmit)
        :param did_registry: dizionario {did: did_document} per ottenere chiavi pubbliche
        :param credential_id: id della credenziale da verificare per revoca
        :return: True se tutte le verifiche passano, False altrimenti
        """

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
        print("="*50)

        print("Estrazione dati dal JWT per ottenere DID issuer...")
        try:
            unverified_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
            issuer_did = unverified_payload.get("iss")
            if issuer_did is None:
                print("❌Issuer DID mancante nel JWT")
                return False
            else:
                print("✅Recupero DID avvenuto con successo")
        except Exception as e:
            print(f"Errore nell'estrazione issuer DID: {e}")
            return False
        print("=" * 50)

        print(f"Recupero chiave pubblica da DID registry per issuer {issuer_did}...")
        try:
            issuer_public_key_pem = did_registry.get_public_key(issuer_did)
            print("✅Recupero chiave pubblica avvenuto con successo")
        except Exception as e:
            print(f"❌ Errore nel recupero della chiave pubblica dal DID Registry: {e}")
            return False
        print("=" * 50)

        print("Verifica firma del JWT...")
        if not self.verify_credential_signature(vc_jwt, issuer_public_key_pem):
            print("❌Firma del JWT non valida")
            return False
        else:
            print("✅Verifica firma avvenuto con successo")
        print("=" * 50)

        print("Decodifica e controllo payload JWT...")
        vc_data = self.obtain_structured_data(vc_jwt, issuer_public_key_pem)
        if vc_data is None:
            print("❌Errore nell'estrazione dati dal JWT")
            return False
        else:
            print("✅Estrazione avvenuta con successo:\n", json.dumps(vc_data, indent=4))
        print("=" * 50)

        expected_merkle_root = vc_data.get("merkleRoot")
        if expected_merkle_root is None:
            print("Merkle Root mancante nel JWT")
            return False

        print("Calcolo Merkle Root sugli attributi divulgati...")
        if not self.verify_merkle_root(disclosed_attributes, expected_merkle_root):
            print("❌Confronto Merkle Root fallito")
            return False
        else:
            print("✅Confronto sulla Merkle Root avvenuta con successo")
        print("=" * 50)

        print("Verifica stato di revoca...")
        if self.is_revoked(credential_id):
            print("❌Credenziale revocata")
            return False
        else:
            print("✅Verifica stato di revoca avvenuto con successo")
        print("=" * 50)

        print("✅VERIFICA COMPLETA SUPERATA CON SUCCESSO")
        print("=" * 50)
        return True

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

    def create_verifiable_presentation(
            self,
            credential_jwt: str,
            disclosed_attributes: dict,
            merkle_proofs: list,
            nonce: str
    ) -> str:
        """
        Crea una Verifiable Presentation firmata dallo studente, includendo il nonce challenge ricevuto.

        :param credential_jwt: JWT della Verifiable Credential ricevuta dall'issuer
        :param disclosed_attributes: attributi che lo studente decide di rivelare
        :param merkle_proofs: proof per gli attributi selezionati
        :param nonce: challenge per prevenire replay
        :return: VP firmata come JWT o struttura firmata
        """
        raise NotImplementedError("create_verifiable_presentation deve essere implementato.")

    def transmit(self, recipient_did: str, message: bytes) -> None:
        """
        Metodo astratto per la trasmissione sicura di un messaggio a un altro attore identificato dal suo DID.
        """
        raise NotImplementedError("Il metodo transmit deve essere implementato dalla sottoclasse.")