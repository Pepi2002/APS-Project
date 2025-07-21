import jwt
from Actors.Actor import Actor
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from OtherTechnologies.MerkleTree import MerkleTree


class Verifier(Actor):
    """Classe che simula il destinatario della verifiable presentation"""

    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)
        self.nonce_registry = set() #Registro dei nonce per verificare il replay attack

    def decrypt_presentation(self, encrypted_package: bytes):
        """
        Metodo che si occupa di decifrare il pacchetto trasmesso
        :param encrypted_package: il pacchetto cifrato trasmesso
        :return: il pacchetto decifrato (attributi in chiaro, vp payload, vp in jwt)
        """
        print("Decriptazione pacchetto...")
        try:
            #Decifra tramite crittografia ibrida
            decrypted_payload = self.hybrid_crypto.decrypt(encrypted_package, self.get_private_key_pem())
            decrypted_json_str = decrypted_payload.decode() #converte in str
            vp_jwt = decrypted_json_str
        except Exception as e:
            print(f"❌Errore durante la decriptazione: {e}")
            return None

        try:
            #Ottiene il payload
            vp_payload = jwt.decode(vp_jwt, options={"verify_signature": False})
            disclosed_attributes = vp_payload.get("studentData") #Gli attributi selezionati dallo studente

            #Controlla la validità degli attributi selezionati
            if not disclosed_attributes:
                print("❌Attributi non presenti nel payload della VP")
                return None

            print("✅Decriptazione avvenuta con successo")
            return disclosed_attributes, vp_payload, vp_jwt
        except Exception as e:
            print(f"❌Errore parsing VP JWT: {e}")
            return None

    def check_revocation(self, vc_jwt: str) -> bool:
        """
        Verifica che la credenziale non sia stata revocata
        :param vc_jwt: verifiable credential sulla quale controllare la revoca
        :return: true se è revocata, altrimenti false
        """
        print("Verifica revoca credenziale...")
        try:
            #Ottiene il payload della vc
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})

            #Ottiene l'id della credenziale
            credential_id = vc_payload.get("jti")

            #Controlla la validità dell'id
            if not credential_id:
                print("❌ID della credenziale (jti) mancante nella VC")
                return False

            #Controlla se è revocata tramite il revocation registry
            if self.revocation_registry.is_revoked(credential_id):
                print("❌Credenziale revocata (verificato via blockchain)")
                return False
            print("✅Credenziale attiva e non revocata")
            return True
        except Exception as e:
            print(f"❌Errore durante la verifica revoca: {e}")
            return False

    def verify_nonce(self, nonce: str) -> bool:
        """
        Verifica che non ci sia stato un replay attack
        :param nonce: il nonce da verificare
        :return: true se il nonce non è presente nel registro, altrimenti false
        """
        print("Verifica nonce...")

        #Controlla la validità del nonce
        if not nonce:
            print("❌Nonce mancante nella VP")
            return False

        #Controlla la presenza del nonce nel registro
        if nonce in self.nonce_registry:
            print(f"❌Nonce già usato ({nonce}), possibile replay attack.")
            return False

        #Aggiunge il nonce nel registro
        self.nonce_registry.add(nonce)
        print("✅Nonce verificato e registrato")
        return True

    def verify_holder_signature(self, vp_jwt: str) -> bool:
        """
        Verifica la firma dello studente
        :param vp_jwt: La verifiable presentation in jwt
        :return: true se la verifica va a buon fine, altrimenti false
        """
        print("Verifica firma dello studente (holder)...")
        try:
            #Ottiene il payload della vp
            unverified_payload = jwt.decode(vp_jwt, options={"verify_signature": False})

            #Ottiene il did dello studente
            holder_did = unverified_payload.get("iss")

            #Controlla la validità del did
            if not holder_did:
                print("❌DID dello studente mancante nella VP")
                return False

            #Ottiene la chiave pubblica dello studente tramite il did registry
            holder_pubkey_pem = self.did_registry.get_public_key(holder_did)

            #Controlla la firma
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
        """
        Verifica la firma del mittente e se questo è certificato
        :param vc_jwt: la verifiable credential in jwt passata insieme alla verifiable presentation
        :return: il payload della vc e il did dell'issuer
        """
        print("Verifica firma dell’issuer e del certificato...")
        try:
            #Ottiene il payload della vc
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})

            #Ottiene il did del mittente e dell'ente di accreditamento
            issuer_did = vc_payload.get("iss")
            authority_did = vc_payload.get("acc")

            #Controlla la validità dei did
            if not issuer_did or not authority_did:
                print("❌Campi 'iss' o 'acc' mancanti nella VC.")
                return None

            #Ottiene la chiave pubblica dell'ente di accreditamento
            authority_pubkey = self.did_registry.get_public_key(authority_did)

            #Ottiene il certificato del mittente
            certificate_jwt = self.did_registry.get_certificate(issuer_did)

            #Ottiene il payload del certificato
            certificate_payload = jwt.decode(certificate_jwt, authority_pubkey, algorithms=["RS256"])

            #Controlla che il certifica corrisponde al mittente
            if certificate_payload.get("sub") != issuer_did:
                print("❌Il certificato non accredita correttamente l'issuer.")
                return None

            #Ottiene la chiave pubblica del mittente
            issuer_pubkey = self.did_registry.get_public_key(issuer_did)

            #Verifica l firma sul vc originale
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
        """
        Verifica la merkle root usando le merkle proof e i dati selezionati passati tramite la vp
        :param vp_payload: il payload della verifiable presentation
        :return: true se la verifica va a buon fine, altrimenti false
        """
        print("Verifica Merkle root...")

        try:
            #Ottiene gli attributi selezionati
            disclosed_attributes = vp_payload.get("studentData")

            #Ottiene i merkle proofs
            merkle_proofs = vp_payload.get("merkleProofs", {})

            #Ottiene la vc
            vc_jwt = vp_payload.get("verifiableCredential")

            #Controlla la validità di tutti e tre
            if not disclosed_attributes or not merkle_proofs or not vc_jwt:
                print("❌Dati mancanti nella VP (studentData, merkleProofs o verifiableCredential)")
                return False

            #Ottiene il payload della vc
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})

            #Ottiene la root della credenziale originale
            expected_root = vc_payload.get("merkleRoot")

            #Controlla la validità del merkle root ottenuto
            if not expected_root:
                print("❌Merkle root mancante nella VC")
                return False

            #Appiattisce i dati
            flat_disclosed = dict(MerkleTree.flatten_data(disclosed_attributes))

            #Itera sui dati appiattiti
            for path, proof in merkle_proofs.items():
                #Controlla la validità dell'attributo
                if path not in flat_disclosed:
                    print(f"❌Attributo {path} non trovato tra gli attributi rivelati")
                    return False

                #Ricostruisce l'hash della foglia del merkle tree
                leaf_data = {"path": path, "value": flat_disclosed[path]}
                leaf_hash = MerkleTree.hash_data(leaf_data)

                #Controlla che il leaf hash insieme alla proof ricostruisce la merkle root
                if not MerkleTree.verify_proof(leaf_hash, proof, expected_root):
                    print(f"❌Merkle proof fallita per attributo: {path}")
                    return False

            print("✅Tutte le Merkle Proofs verificate con successo")
            return True

        except Exception as e:
            print(f"❌ Errore durante la verifica della Merkle root: {e}")
            return False

    def verify_presentation(self, encrypted_package: bytes):
        """
        Ciclo principa di verifica che controlla la verifiable presentation
        :param encrypted_package: pacchetto criptato da verificare
        :return: true se la verifica è andata a buon fine, altrimenti false
                 e poi una coppia (attributi selezionati, vp in jwt)
        """
        print("Avvio processo di verifica della Verifiable Presentation")
        print("=" * 60)
        #Decifra il pacchetto trasmesso
        result = self.decrypt_presentation(encrypted_package)

        #Verifica la validità del risultato della decifratura
        if not result:
            return False, None, None
        disclosed_attributes, vp_payload, vp_jwt = result

        #Verifica la revoca della credenziale
        if not self.check_revocation(vp_payload.get("verifiableCredential")):
            return False, None, None

        #Verifica la possibilità di un replay attack
        if not self.verify_nonce(vp_payload.get("nonce")):
            return False, None, None

        #Verifica la firma dello studente
        if not self.verify_holder_signature(vp_jwt):
            return False, None, None

        #Verifica la firma del mittente e il certificato
        issuer_info = self.verify_issuer_signature(vp_payload.get("verifiableCredential"))

        #Verifica la validità della verifica
        if not issuer_info:
            return False, None, None

        #Verifica la merkle root e la merkle proof
        if not self.verify_merkle_root_from_vp(vp_payload):
            return False, None, None

        print("\n✅Tutte le verifiche superate con successo")
        print("=" * 60)
        return True, disclosed_attributes, vp_jwt
