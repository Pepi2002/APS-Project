from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from OtherTechnologies.NumberGenerator import CSPRNGGenerator


class HybridCrypto:
    def __init__(self):
        self.number_gen = CSPRNGGenerator() #Generatore di numeri casuali

    def encrypt(self, plaintext: bytes, recipient_public_key_pem: bytes) -> bytes:
        """
        Si occupa di cifrare il plaintext svolgendo una crittografia ibrida e usando
        la chiave pubblica del destinatario
        :param plaintext: il plaintext da cifrare
        :param recipient_public_key_pem: la chiave pubblica da usare per la crittografia
        :return: il plaintext cifrato
        """
        #Genero la chiave simmetrica usando il generatore di numeri casuali
        sym_key = self.number_gen.generate_session_key()

        #Genero l'inizialization vector usando il generatore di numeri casuali
        iv = self.number_gen.generate_key_material(16)

        #Cifro il messaggio usando la modalità CTR
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(plaintext) + encryptor.finalize()

        #Carico la chiave pubblica per usare la crittografia asimmetrica
        public_key = serialization.load_pem_public_key(recipient_public_key_pem)

        #Cifro la chiave usando la crittografia asimmetrica
        encrypted_sym_key = public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        len_enc_sym_key = len(encrypted_sym_key).to_bytes(2, byteorder='big')

        #Ritorno il pacchetto cifrato completo
        return len_enc_sym_key + encrypted_sym_key + iv + encrypted_data

    def decrypt(self, encrypted_package: bytes, recipient_private_key_pem: bytes) -> bytes:
        """
        Si occupa di decifrare il plaintext svolgendo una crittografia ibrida e usando
        la chiave privata del destinatario
        :param encrypted_package: il plaintext da decifrare
        :param recipient_private_key_pem: la chiave privata da usare per la decrittografia
        :return: il pacchetto decifrato
        """
        #Estrae la lunghezza della chiave cifrata
        len_enc_sym_key = int.from_bytes(encrypted_package[0:2], byteorder='big')

        #Estrae la chiave simmetrica, l'Inizialization vector e i dati cifrati
        encrypted_sym_key = encrypted_package[2:2 + len_enc_sym_key]
        iv = encrypted_package[2 + len_enc_sym_key: 2 + len_enc_sym_key + 16]
        encrypted_data = encrypted_package[2 + len_enc_sym_key + 16:]

        #Carica la chiave privata da usare per la cifratura
        private_key = serialization.load_pem_private_key(recipient_private_key_pem, password=None)

        #Decifra la chiave simmetrica usando la crittografia asimmetrica
        sym_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #Ottengo il plaintext originale usando la chiave simmetrica
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        return plaintext