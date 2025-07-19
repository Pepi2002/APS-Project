import json

# Assumendo che le nuove classi siano in un file chiamato Blockchain.py
# o che tu le abbia spostate nel file SimulatedBlockchain.py esistente
# Fai attenzione ai percorsi di importazione
from ActorsPepi.AccreditationAuthority import AccreditationAuthority
from ActorsPepi.Issuer import Issuer
from ActorsPepi.Student import Student
from ActorsPepi.Verifier import Verifier
from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry
# Importa la nuova classe Blockchain (NON SimulatedBlockchain)
from BlockchainRaff.Blockchain import Blockchain # O il percorso corretto al tuo file Blockchain.py
from OtherTechnologiesPepi.MerkleTree import MerkleTree
from Utils.CredentialUtils import CredentialUtils


def main():
    # Inizializza la nuova classe Blockchain
    blockchain = Blockchain()
    print("✅CREAZIONE DELLA BLOCKCHAIN SIMULATA (con PoW) AVVENUTA CON SUCCESSO")
    did_registry = DIDRegistry(blockchain)
    print("✅CREAZIONE DEL REGISTRO PER IL SALVATAGGIO DEI DID AVVENUTA CON SUCCESSO")
    revocation_registry = RevocationRegistry(blockchain)
    print("✅CREAZIONE DEL REGISTRO PER LA REVOCA AVVENUTA CON SUCCESSO")
    print("=" * 50)

    issuer = Issuer()
    print("✅CREAZIONE DELL'ISSUER AVVENUTA CON SUCCESSO")
    student = Student()
    print("✅CREAZIONE DELLO STUDENTE AVVENUTA CON SUCCESSO")
    verifier = Verifier()
    print("✅CREAZIONE DEL VERIFIER AVVENUTA CON SUCCESSO")
    accreditation_authority = AccreditationAuthority()
    print("✅CREAZIONE DELL'ENTE DI ACCREDITAMENTO AVVENUTA CON SUCCESSO")
    print("=" * 50)

    # --- FASE 1: Generazione DID e Transazioni in Sospeso ---
    did_issuer = issuer.generate_did(did_registry)
    # Le transazioni DID sono ora in 'pending_transactions' della blockchain

    did_student = student.generate_did(did_registry)
    did_verifier = verifier.generate_did(did_registry)
    did_authority = accreditation_authority.generate_did(did_registry)

    # Nota: I documenti DID verranno recuperati solo dopo che le transazioni saranno minate
    # Quindi, i print dei documenti DID li sposteremo dopo il mining.
    # Per ora, stampa solo il fatto che i DID sono stati generati.
    print(f"DID generati. Transazioni in sospeso: {len(blockchain.pending_transactions)}")
    print("=" * 50)

    # --- FASE 2: Mining del primo blocco per includere i DID ---
    print("\n--- Mining del blocco per le registrazioni DID ---")
    blockchain.mine_pending_transactions(mining_reward_address="univer_miner_1")
    print("=" * 50)

    # Ora che i DID sono sulla blockchain (simulata), puoi recuperarli
    doc_issuer = did_registry.get_did_document(did_issuer)
    print("DOCUMENTO DID PER L'ISSUER:", json.dumps(doc_issuer, indent=4))
    print("=" * 50)
    doc_student = did_registry.get_did_document(did_student)
    print("DOCUMENTO DID PER LO STUDENTE:", json.dumps(doc_student, indent=4))
    print("=" * 50)
    doc_verifier = did_registry.get_did_document(did_verifier)
    print("DOCUMENTO DID PER IL VERIFIER:", json.dumps(doc_verifier, indent=4))
    print("=" * 50)
    doc_authority = did_registry.get_did_document(did_authority)
    print("DOCUMENTO DID PER L'ENTE DI ACCREDITAMENTO:", json.dumps(doc_authority, indent=4))
    print("=" * 50)

    # --- FASE 3: Richieste di Accreditamento (creano transazioni) ---
    issuer.request_accreditation(accreditation_authority)
    # is_did_accredited ora leggerà dalla blockchain, quindi serve il mining
    print(f"Transazioni in sospeso dopo richiesta accreditamento Issuer: {len(blockchain.pending_transactions)}")

    verifier.request_accreditation(accreditation_authority)
    print(f"Transazioni in sospeso dopo richiesta accreditamento Verifier: {len(blockchain.pending_transactions)}")
    print("=" * 50)

    # --- FASE 4: Mining del blocco per le accreditazioni ---
    print("\n--- Mining del blocco per le accreditazioni ---")
    blockchain.mine_pending_transactions(mining_reward_address="univer_miner_2")
    print("=" * 50)

    # Ora verifica gli accreditamenti
    if accreditation_authority.is_did_accredited(did_issuer):
        print("✅ACCREDITAMENTO DELL'ISSUER AVVENUTA CON SUCCESSO")
    else:
        print("ACCREDITAMENTO NON AVVENUTO")
    print("=" * 50)

    if accreditation_authority.is_did_accredited(did_verifier):
        print("✅ACCREDITAMENTO DEL VERIFIER AVVENUTA CON SUCCESSO")
    else:
        print("ACCREDITAMENTO NON AVVENUTO")
    print("=" * 50)


    print("Caricamento dati Mock per Simulazione ...")
    data = CredentialUtils.load_mock_student_data()
    print(json.dumps(data, indent=4))
    print("=" * 50)

    print("Creazione MerkleTree e calcolo Merkle Root...")
    merkle_tree = MerkleTree(data)
    print("✅CREAZIONE MERKLE TREE AVVENUTA CON SUCCESSO")
    merkle_root = merkle_tree.get_merkle_root()
    print("merkle root: ", merkle_root)
    print("=" * 50)

    print("Creazione della Verifiable Credential da parte dell'Issuer ...")
    verifiable_credential = issuer.create_verifiable_credential(did_student, merkle_root)
    print(f"✅CREAZIONE VC AVVENUTA CON SUCCESSO:  {verifiable_credential[:60]}...")
    print("=" * 50)

    message = {
        "vc": verifiable_credential,
        "data": data
    }

    message_json = json.dumps(message, indent=4)
    message_json = message_json.encode('utf-8')

    print("Trasmissione della credenziale allo Studente...")
    encrypted_data = issuer.transmit(did_student, message_json, did_registry)
    print("✅TRASMISSIONE VC AVVENUTA CON SUCCESSO")
    print("=" * 50)

    print("Processo di verifica in Corso...")
    # Qui, student.verify_credential e Verifier.verify_credential dovranno
    # usare i registri che a loro volta leggono dalla blockchain
    student.verify_credential(encrypted_data, did_registry, "")
    # verifier.verify_credential(...) # Assicurati che anche il Verifier usi il DIDRegistry e RevocationRegistry correttamente


    # Aggiungi un esempio di revoca e relativo mining
    print("\n--- Simulazione Revoca Credenziale ---")
    credential_id_to_revoke = "credential:mock_credential_id_1" # Esempio di ID credenziale
    revocation_registry.revoke_credential(credential_id_to_revoke)
    print(f"Transazioni in sospeso dopo richiesta revoca: {len(blockchain.pending_transactions)}")
    print("=" * 50)

    # --- FASE 5: Mining del blocco per le revoche (e altre transazioni) ---
    print("\n--- Mining del blocco per le revoche ---")
    blockchain.mine_pending_transactions(mining_reward_address="univer_miner_3")
    print("=" * 50)

    # Ora verifica lo stato di revoca
    print(f"La credenziale '{credential_id_to_revoke}' è revocata? {revocation_registry.is_revoked(credential_id_to_revoke)}")
    print("=" * 50)


    print("\n--- Verifica finale dell'integrità della Blockchain ---")
    print(f"La blockchain è valida? {blockchain.is_chain_valid()}")
    print("=" * 50)

    # Puoi anche stampare la catena completa per debugging
    # for block in blockchain.chain:
    #     print(f"Blocco #{block.index}, Hash: {block.hash}, Transazioni: {len(block.transactions)}")
    #     for tx in block.transactions:
    #         print(f"  - {tx.get('type')}")


if __name__ == "__main__":
    main()