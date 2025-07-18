import secrets

class CSPRNGGenerator:
    """Generatore di Numeri Pseudo Casuali Crittograficamente Sicuro"""

    @staticmethod
    def generate_key_material(length: int) -> bytes:
        """Genera materiale crittografico sicuro"""
        return secrets.token_bytes(length)

    @staticmethod
    def generate_nonce() -> str:
        """Genera un nonce unico per prevenire replay attacks"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_session_key() -> bytes:
        """Genera una chiave di sessione AES-256"""
        return secrets.token_bytes(32)  # 256 bits
