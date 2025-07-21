import json
from typing import Dict, Any

import jwt

from Actors.Actor import Actor
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from OtherTechnologies.CSPRNGGenerator import CSPRNGGenerator
from OtherTechnologies.MerkleTree import MerkleTree
from OtherTechnologies.StudentDApp import StudentDApp
from Utils.CredentialUtils import CredentialUtils


class Student(Actor):
    """Classe che simula lo studente che riceve la verifiable credential e crea la verifiable presentation"""
    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry, student_dapp: StudentDApp):
        super().__init__(did_registry, revocation_registry)
        self.student_dapp = student_dapp


    def decrypting_package(self, encrypted_package: bytes):
        """
        Metodo che si occupa di decifrare il pacchetto trasmesso
        :param encrypted_package: il pacchetto cifrato trasmesso
        :return: il pacchetto decifrato (attributi in chiaro, vc in jwt)
        """
        print("Decriptazione pacchetto...")
        try:
            #Decifra tramite critoografia ibrida
            decrypted_payload = self.hybrid_crypto.decrypt(encrypted_package, self.get_private_key_pem())
            decrypted_json_str = decrypted_payload.decode() #Converte i bytes in str
            decrypted_data = json.loads(decrypted_json_str) #Converte str in json
            disclosed_attributes = decrypted_data["data"] #Ottiene gli attributi in chiaro
            vc_jwt = decrypted_data["vc"] #Ottiene la vc
        except Exception as e:
            print(f"Errore durante la decriptazione: {e}")
            return False

        #Controlla la validità degli attributi in chiaro e della vc
        if disclosed_attributes is None or vc_jwt is None:
            print("❌Dati mancanti nel pacchetto decriptato")
            return False
        else:
            print("✅Decriptazione avvenuta con successo")

        return disclosed_attributes, vc_jwt

    def is_revoked(self, vc_jwt: str) -> bool:
        """
        Verifica se la VC è stata revocata estraendo l'ID (jti) dal JWT.
        :param vc_jwt: JWT della Verifiable Credential
        :return: true se la verifica va a buon fine, altrimenti false
        """
        try:
            #Ottiene il payload
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})

            #Ottiene l'id della credenziale
            credential_id = vc_payload.get("jti")

            #Controlla la validità dell'id
            if not credential_id:
                print("❌ ID della credenziale (jti) mancante nel VC")
                return True  # Trattiamo l'assenza di jti come revocata per sicurezza

            #Ritorna il controllo fatto dal revocation registry tramite l'id
            return self.revocation_registry.is_revoked(credential_id)
        except Exception as e:
            print(f"❌ Errore durante verifica revoca: {e}")
            return True  # In caso di errore, assumiamo revoca per sicurezza

    def verify_accreditation_certificate(self, vc_payload):
        """
        Verifica la validità del mittente controllandone il certificato
        :param vc_payload: il payload della vc in cui è presente il did del mittente
        :return: true se il certificato ne attesta la validità, altriemnti false
        """
        #Ottiene il did del mittente e il did dell'ente di accreditamento
        print("Verifica di certificazione dell'issuer...")
        issuer_did = vc_payload.get("iss")
        authority_did = vc_payload.get("acc")

        #Controlla la validità dei did
        if not issuer_did or not authority_did:
            print("❌VC mancante di campo 'iss' o 'acc'")
            return False

        try:
            #Ottiene la chiave pubblica dell'ente di accreditamento
            authority_pubkey = self.did_registry.get_public_key(authority_did)

            #Ottiene il certificato del mittente
            certificate_jwt = self.did_registry.get_certificate(issuer_did)

            #Controlla la validità del certificato
            if not certificate_jwt:
                print("❌Nessun certificato di accreditamento trovato per l'issuer")
                return False

            #Ottiene il payload del certificato
            payload = jwt.decode(certificate_jwt, authority_pubkey, algorithms=["RS256"])

            #Controlla che il certificato corrisponde al mittente
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
        Verifica la firma digitale del Verifiable Credential JWT ricevuto
        :param vc_jwt: La vc in jwt da usare per verifiacre la firma
        :param issuer_public_key_pem: la chaive pubblica del mittente per verificare la firma
        """
        print("Verifica sull'integrità della verifiable credential...")
        try:
            #Verifica la firma
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
            #Ottiene il payload della vc
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})

            #Ottiene la merkle root
            expected_root = vc_payload.get("merkleRoot")

            #Controlla la validità della merkle root
            if not expected_root:
                print("❌Merkle root mancante nel VC")
                return False

            #Crea un merkle tree usando gli attributi in chiaro
            merkle_tree = MerkleTree(disclosed_attributes)

            #Ottiene il merkle tree
            calculated_root = merkle_tree.get_merkle_root()

            #Controlla se sono uguali e quindi l'integrità degli attributi in chiaro
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

    def verify_credential(self, encrypted_package: bytes):
        """
        Verifica completa della credenziale partendo dal pacchetto criptato ricevuto.

        :param encrypted_package: dati cifrati ricevuti dallo issuer (es. dal metodo transmit)
        :param credential_id: id della credenziale da verificare per revoca
        :return: True se tutte le verifiche passano, False altrimenti
        """
        #Decifra il pacchetto
        result = self.decrypting_package(encrypted_package)

        #Controlla che la decifratura sia andata a buon fine
        if not result:
            return False, None, None
        disclosed_attributes, vc_jwt = result

        # Controlla la revoca della credenziale
        print("Verifica sulla validità del messaggio...")
        if self.is_revoked(vc_jwt):
            print("❌Credenziale revocata")
            return False, None, None
        else:
            print("✅Credenziale attiva e non revocata")

        try:
            #Ottiene il payload della vc
            vc_payload = jwt.decode(vc_jwt, options={"verify_signature": False})
        except Exception as e:
            print(f"Errore parsing VC JWT: {e}")
            return False, None, None

        #Verifica il certificato del mittente
        self.verify_accreditation_certificate(vc_payload)

        #Ottiene il did del mittente
        issuer_did = vc_payload.get("iss")
        try:
            #Ottiene la chiave pubblica del mittente
            issuer_pubkey = self.did_registry.get_public_key(issuer_did)

            #Controlla la firma del mittente
            if not self.verify_credential_signature(vc_jwt, issuer_pubkey):
                print("❌Firma della VC non valida")
                return False, None, None
            print("✅Firma della VC verificata")
        except Exception as e:
            print(f"Errore ottenimento chiave pubblica issuer: {e}")
            return False, None, None

        #Controlla la merkle root
        if not self.verify_merkle_root_from_vc(vc_jwt, disclosed_attributes):
            return False, None, None

        print("\n✅Tutte le verifiche superate con successo")
        print("="*50)
        return True, disclosed_attributes, vc_jwt

    def store_credential_in_dapp(self, disclosed_attributes: dict, vc_jwt: str):
        """
        Metodo per salvare le credenziale nella DApp dello studente
        :param disclosed_attributes: gli attributi in chiaro da salvare
        :param vc_jwt: la vc_jwt da salvare
        """
        self.student_dapp.store_credential(disclosed_attributes, vc_jwt)

    def create_verifiable_presentation(self, vc_jwt: str, verifier_did: str):
        """
        Metodo per creare una verifiable presentation
        :param vc_jwt: la vc jwt originale
        :param verifier_did: il did del destinatario
        :return: la vp creata e gli attributi selezionati dallo studente
        """
        #Caricamento dei dati dalla DApp
        full_credential = self.student_dapp.get_credential()

        #Attributi in chiaro ricevuti
        full_vc_data = full_credential["disclosed_attributes"]

        #Selezione da parte dello studente degli attributi che vuole divulgare
        disclosed_attributes = self.student_dapp.select_attributes()

        #Creazione del merkle tree a partire degli attributi in chiaro
        merkle_tree = MerkleTree(full_vc_data)

        #Calcolo delle merkle proof degli attributi selezionati
        merkle_proofs = {}
        #Appiattisce i dati
        flat_disclosed = merkle_tree.flatten_data(disclosed_attributes)

        #Cicla sui dati appiattiti
        for path, value in flat_disclosed:
            #Calcola la proof per l'attributo
            proof_result = merkle_tree.calculate_merkle_proof(path)
            if proof_result:
                #Ottiene il risultato della proof
                leaf_value, proof_path = proof_result
                if leaf_value == value:
                    #Aggiunge alla lista da mettere nella vp
                    merkle_proofs[path] = proof_path
                else:
                    print(f"❌Attenzione: valore differto per {path}")

        #Genera un nonce per prevenire replay attack
        nonce = CSPRNGGenerator.generate_nonce()

        #Crea la verifiable presentation
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
        :param recipient_did: did del destinatario
        :param message: messaggi della trasmissione
        """
        try:
            #Ottiene la chiave pubblica del destinatario
            recipient_pubkey_pem = self.did_registry.get_public_key(recipient_did)
        except Exception as e:
            print(f"Errore risoluzione DID {recipient_did}: {e}")
            return None

        #Codifica il messaggio in bytes
        message = message.encode('utf-8')

        #Cifra il messaggio tramite crittografia ibrida
        encrypted_message = self.hybrid_crypto.encrypt(message, recipient_pubkey_pem)
        print(f"Invio messaggio cifrato a {recipient_did}:\n{encrypted_message.hex()[:60]}...")
        return encrypted_message
