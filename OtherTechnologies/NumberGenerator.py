import secrets

class CSPRNGGenerator:

    @staticmethod
    def generate_key_material(length: int) -> bytes:
        return secrets.token_bytes(length)

    @staticmethod
    def generate_nonce() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_session_key() -> bytes:
        return secrets.token_bytes(32)  # 256 bits
