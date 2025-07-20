import datetime
import jwt

from ActorsPepi.Actor import Actor
from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry


class AccreditationAuthority(Actor):
    def __init__(self, did_registry: DIDRegistry, revocation_registry: RevocationRegistry):
        super().__init__(did_registry, revocation_registry)

    def generate_accreditation_certificate(self, did: str, exp_days: int = 365) -> str:
        """
        Genera un certificato JWT di accreditamento per un DID,
        firmato dall'Authority.
        """

        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": did,
            "iss": self.get_did(),
            "iat": int(now.timestamp()),
            "exp": int((now + datetime.timedelta(days=exp_days)).timestamp()),
            "type": "AccreditationCertificate"
        }

        headers = {
            "alg": "RS256",
            "typ": "JWT"
        }

        return jwt.encode(payload, self.get_private_key_pem(), algorithm="RS256", headers=headers)