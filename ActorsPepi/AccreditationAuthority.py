import datetime
import jwt

from ActorsPepi.Actor import Actor


class AccreditationAuthority(Actor):
    def __init__(self):
        super().__init__()
        self.registered_entities = {}

    def register_entity(self, did: str, public_key_pem):
        if did in self.registered_entities:
            raise ValueError(f"DID {did} è già registrato.")
        self.registered_entities[did] = public_key_pem

    def is_did_accredited(self, did: str) -> bool:
        """Controlla se un DID è accreditato."""
        return did in self.registered_entities

    def generate_accreditation_certificate(self, did: str, exp_days: int = 365) -> str:
        """
        Genera un certificato JWT di accreditamento per un DID,
        firmato dall'Authority.
        """
        if not self.is_did_accredited(did):
            raise ValueError(f"DID {did} non accreditato")

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