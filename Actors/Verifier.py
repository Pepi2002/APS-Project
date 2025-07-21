import jwt
from Actors.Actor import Actor
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from OtherTechnologies.MerkleTree import MerkleTree


class Verifier(Actor):
    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)
        self.nonce_registry = set()

    def decrypt_presentation(self, encrypted_package: bytes):
        print("Decriptazione pacchetto...")
        try:
            decrypted_payload = self.hybrid_crypto.decrypt(encrypted_package, self.get_private_key_pem())
            decrypted_json_str = decrypted_payload.decode()
            vp_jwt = decrypted_json_str
        except Exception as e:
            print(f"❌Errore durante la decriptazione: {e}")
            return None

        try:
            vp_payload = jwt.decode(vp_jwt, options={"verify_signature": False})
            disclosed_attributes = vp_payload.get("studentData")
            if not disclosed_attributes:
                print("❌Attributi non presenti nel payload della VP")
                return None

            print("✅Decriptazione avvenuta con successo")
            return disclosed_attributes, vp_payload, vp_jwt
        except Exception as e:
            print(f"❌Errore parsing VP JWT: {e}")
            return None

    def verify_nonce(self, nonce: str) -> bool:
        print("Verifica nonce...")
        if not nonce:
            print("❌Nonce mancante nella VP")
            return False
        if nonce in self.nonce_registry:
            print(f"❌Nonce già usato ({nonce}), possibile replay attack.")
            return False
        self.nonce_registry.add(nonce)
        print("✅Nonce verificato e registrato")
        return True

    def verify_holder_signature(self, vp_jwt: str) -> bool:
        print("Verifica firma dello studente (holder)...")
        try:
            unverified_payload = jwt.decode(vp_jwt, options={"verify_signature": False})
            holder_did = unverified_payload.get("iss")
            if not holder_did:
                print("❌DID dello studente mancante nella VP")
                return False

            holder_pubkey_pem = self.did_registry.get_public_key(holder_did)
            jwt.decode(vp_jwt, holder_pubkey_pem, algorithms=["RS256"], audience=self.get_did())
            print("✅Firma dello studente verificata")
            return True
        except jwt.InvalidSignatureError:
            print("❌Firma dello studente non valida")
            return False
        except Exception as e:
            print(f"❌Errore durante la verifica della firma holder: {e}")
            return False

    def verify_issuer_signature(self, vc_jwt: str):
        print("Verifica firma dell’issuer e del certificato...")
        try:
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
            issuer_did = vc_payload.get("iss")
            authority_did = vc_payload.get("acc")
            if not issuer_did or not authority_did:
                print("❌Campi 'iss' o 'acc' mancanti nella VC.")
                return None

            authority_pubkey = self.did_registry.get_public_key(authority_did)
            certificate_jwt = self.did_registry.get_certificate(issuer_did)
            certificate_payload = jwt.decode(certificate_jwt, authority_pubkey, algorithms=["RS256"])
            if certificate_payload.get("sub") != issuer_did:
                print("❌Il certificato non accredita correttamente l'issuer.")
                return None

            issuer_pubkey = self.did_registry.get_public_key(issuer_did)
            jwt.decode(vc_jwt, issuer_pubkey, algorithms=["RS256"])

            print("✅Certificato e firma issuer validi")
            return vc_payload, issuer_did

        except jwt.ExpiredSignatureError:
            print("❌Il certificato è scaduto.")
        except jwt.InvalidSignatureError:
            print("❌Firma non valida.")
        except Exception as e:
            print(f"❌Errore verifica issuer: {e}")

        return None

    @staticmethod
    def verify_merkle_root_from_vp(vp_payload: dict) -> bool:
        print("Verifica Merkle root...")

        try:
            disclosed_attributes = vp_payload.get("studentData")
            merkle_proofs = vp_payload.get("merkleProofs", {})
            vc_jwt = vp_payload.get("verifiableCredential")

            if not disclosed_attributes or not merkle_proofs or not vc_jwt:
                print("❌Dati mancanti nella VP (studentData, merkleProofs o verifiableCredential)")
                return False

            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
            expected_root = vc_payload.get("merkleRoot")

            if not expected_root:
                print("❌Merkle root mancante nella VC")
                return False

            for proof in merkle_proofs.values():
                if not MerkleTree.verify_merkle_proof(proof, expected_root):
                    print(f"❌Merkle proof fallita per attributo: {proof.get('attribute')}")
                    return False

            print("✅Tutte le Merkle Proofs verificate con successo")
            return True

        except Exception as e:
            print(f"❌ Errore durante la verifica della Merkle root: {e}")
            return False

    def check_revocation(self, vc_jwt: str) -> bool:
        print("Verifica revoca credenziale...")
        try:
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
            credential_id = vc_payload.get("jti")
            if not credential_id:
                print("❌ID della credenziale (jti) mancante nella VC")
                return False
            if self.revocation_registry.is_revoked(credential_id):
                print("❌Credenziale revocata (verificato via blockchain)")
                return False
            print("✅Credenziale attiva e non revocata")
            return True
        except Exception as e:
            print(f"❌Errore durante la verifica revoca: {e}")
            return False

    def verify_presentation(self, encrypted_package: bytes):
        print("Avvio processo di verifica della Verifiable Presentation")
        print("=" * 60)

        result = self.decrypt_presentation(encrypted_package)
        if not result:
            return False, None, None
        disclosed_attributes, vp_payload, vp_jwt = result

        if not self.verify_nonce(vp_payload.get("nonce")):
            return False, None, None

        if not self.verify_holder_signature(vp_jwt):
            return False, None, None

        issuer_info = self.verify_issuer_signature(vp_payload.get("verifiableCredential"))
        if not issuer_info:
            return False, None, None
        vc_payload, issuer_did = issuer_info

        if not self.verify_merkle_root_from_vp(vp_payload):
            return False, None, None

        if not self.check_revocation(vp_payload.get("verifiableCredential")):
            return False, None, None

        print("\n✅Tutte le verifiche superate con successo")
        print("=" * 60)
        return True, disclosed_attributes, vp_jwt
