from ActorsPepi.Actor import Actor
from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry
from Utils.CredentialUtils import CredentialUtils


class Issuer(Actor):
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
            :param did_registry: oggetto o servizio per risolvere DID e ottenere la chiave pubblica
            """
        try:
            recipient_pubkey_pem = self.did_registry.get_public_key(recipient_did)
        except Exception as e:
            print(f"Errore risoluzione DID {recipient_did}: {e}")
            return

        encrypted_message = self.hybrid_crypto.encrypt(message, recipient_pubkey_pem)
        print(f"Invio messaggio cifrato a {recipient_did}:\n{encrypted_message.hex()[:60]}...")
        return encrypted_message