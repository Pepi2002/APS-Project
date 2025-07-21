import datetime
import jwt

from Actors.Actor import Actor
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry


class AccreditationAuthority(Actor):
    """Classe che simula l'ente di accreditamento"""

    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)

    def generate_accreditation_certificate(self, did: str, exp_days: int = 365) -> str:
        """
        Genera un certificato JWT di accreditamento per un DID,
        firmato dall'Authority.
        :param did: did da inserire nel certificato
        :param exp_days: giorni di validità prima della scadenza
        :return: un certificato di accreditamento
        """
        #Ottiene la data attuale
        now = datetime.datetime.now(datetime.timezone.utc)

        #Crea il payload del certificato
        payload = {
            "sub": did,
            "iss": self.get_did(),
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(days=exp_days)).timestamp()),
            "type": "AccreditationCertificate"
        }

        #Crea l'header del certificato
        headers = {
            "alg": "RS256",
            "typ": "JWT"
        }

        #Ritorna il certificato firmato dall'ente di accreditamento tramite la sua chiave pubblica
        return jwt.encode(payload, self.get_private_key_pem(), algorithm="RS256", headers=headers)