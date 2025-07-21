import jwt

from Actors.Actor import Actor
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from Utils.CredentialUtils import CredentialUtils


class Issuer(Actor):
    """Classe che simula il mittente della Verifiable Credential"""

    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)

    def create_verifiable_credential(
            self,
            holder_did: str,
            accreditation_did: str,
            merkle_root: str,
            exp_days: int = 365
    ) -> str:
        """
        Genera una Verifiable Credential firmata da questo issuer.

        :param accreditation_did:
        :param holder_did: DID dello studente (holder)
        :param merkle_root: Merkle root dei dati accademici
        :param exp_days: validità in giorni
        :return: JWT della VC
        """
        issuer_did = self.get_did()

        return CredentialUtils.generate_verifiable_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            accreditation_did=accreditation_did,
            private_key=self.get_private_key_pem().decode(),
            merkle_root=merkle_root,
            exp_days=exp_days
        )

    def transmit(self, recipient_did: str, message: bytes) -> bytes:
        """
        Trasmette un messaggio cifrato al destinatario usando il suo DID per ottenere la chiave pubblica.
        :param recipient_did: DID del destinatario
        :param message: messaggio in bytes da cifrare e inviare
        """
        #Ottiene la chiave pubblica del destinatario
        try:
            recipient_pubkey_pem = self.did_registry.get_public_key(recipient_did)
        except Exception as e:
            print(f"Errore risoluzione DID {recipient_did}: {e}")
            return

        #Cifra il messaggio da inviare tramite crittografia ibrida
        encrypted_message = self.hybrid_crypto.encrypt(message, recipient_pubkey_pem)

        #Simula l'invio del messaggio
        print(f"Invio messaggio cifrato a {recipient_did}:\n{encrypted_message.hex()[:60]}...")
        return encrypted_message

    def revoke_credential(self, vc_jwt: str) -> bool:
        """
        Revoca una Verifiable Credential passando il suo JWT.

        :param vc_jwt: il JWT della Verifiable Credential
        :return: True se la revoca ha avuto successo, False altrimenti
        """
        try:
            print("Revoca in corso...")

            # Decodifica senza verifica della firma
            payload = jwt.decode(vc_jwt, options={"verify_signature": False})

            #Ottiene l'id della credenziale
            credential_id = payload.get("jti")

            #Controlla che l'id sia valido
            if not credential_id:
                print("❌Campo 'jti' mancante nella VC, impossibile revocare.")
                return False

            #Richiede la revoca della credenziale
            success = self.revocation_registry.revoke_credential(credential_id)

            #Controlla che la revoca sia avvenuta con successo
            if success:
                print("✅Revoca avvenuta con successo.")
            else:
                print("❌La revoca non è stata eseguita (potrebbe essere già stata revocata).")

            return success

        except Exception as e:
            print(f"❌Errore durante la revoca della VC: {e}")
            return False
