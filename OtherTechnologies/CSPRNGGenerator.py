import secrets

class CSPRNGGenerator:
    """Classe che simula il generatore di numeri casuali"""

    @staticmethod
    def generate_key_material(length: int) -> bytes:
        """
        Genera un inizialization vector in maniera casuale
        :param length: la lunghezza dell'inzialization vector
        :return: l'inizialization vector
        """
        return secrets.token_bytes(length)

    @staticmethod
    def generate_nonce() -> str:
        """
        Genera un nonce in modo casuale da usare per controllare che
        non ci siano replay attack
        :return: il nonce generato
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_session_key() -> bytes:
        """
        Genera una chiave simmetrica da usare per la crittografia ibrida
        :return: la chiave simmetrica
        """
        return secrets.token_bytes(32)