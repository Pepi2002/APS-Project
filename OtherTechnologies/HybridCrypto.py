from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from OtherTechnologies.NumberGenerator import CSPRNGGenerator


class HybridCrypto:
    def __init__(self):
        self.number_gen = CSPRNGGenerator()

    def encrypt(self, plaintext: bytes, recipient_public_key_pem: bytes) -> bytes:
        sym_key = self.number_gen.generate_session_key()
        nonce = self.number_gen.generate_key_material(16)
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(plaintext) + encryptor.finalize()

        public_key = serialization.load_pem_public_key(recipient_public_key_pem)
        encrypted_sym_key = public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        len_enc_sym_key = len(encrypted_sym_key).to_bytes(2, byteorder='big')
        return len_enc_sym_key + encrypted_sym_key + nonce + encrypted_data

    def decrypt(self, encrypted_package: bytes, recipient_private_key_pem: bytes) -> bytes:
        len_enc_sym_key = int.from_bytes(encrypted_package[0:2], byteorder='big')
        encrypted_sym_key = encrypted_package[2:2 + len_enc_sym_key]
        nonce = encrypted_package[2 + len_enc_sym_key: 2 + len_enc_sym_key + 16]
        encrypted_data = encrypted_package[2 + len_enc_sym_key + 16:]

        private_key = serialization.load_pem_private_key(recipient_private_key_pem, password=None)
        sym_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        return plaintext