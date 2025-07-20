import json

from ActorsPepi.AccreditationAuthority import AccreditationAuthority
from ActorsPepi.Issuer import Issuer
from ActorsPepi.Student import Student
from ActorsPepi.Verifier import Verifier
from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry
from BlockchainRaff.Blockchain import Blockchain
from OtherTechnologiesPepi.MerkleTree import MerkleTree
from Utils.CredentialUtils import CredentialUtils


def main():

    blockchain = Blockchain()
    print("✅CREAZIONE DELLA BLOCKCHAIN SIMULATA (con PoW) AVVENUTA CON SUCCESSO")
    did_registry = DIDRegistry(blockchain)
    print("✅CREAZIONE DEL REGISTRO PER IL SALVATAGGIO DEI DID AVVENUTA CON SUCCESSO")
    revocation_registry = RevocationRegistry(blockchain)
    print("✅CREAZIONE DEL REGISTRO PER LA REVOCA AVVENUTA CON SUCCESSO")
    print("=" * 50)

    issuer = Issuer(did_registry, revocation_registry)
    print("✅CREAZIONE DELL'ISSUER AVVENUTA CON SUCCESSO")
    did_issuer = issuer.get_did()
    doc_issuer = issuer.get_did_document()
    print(f"did: {did_issuer}")
    print(f"did_document: {json.dumps(doc_issuer, indent=4)}")
    print("=" * 50)

    student = Student(did_registry, revocation_registry)
    print("✅CREAZIONE DELLO STUDENTE AVVENUTA CON SUCCESSO")
    did_student = student.get_did()
    doc_student = student.get_did_document()
    print(f"did: {did_student}")
    print(f"did_document: {json.dumps(doc_student, indent=4)}")
    print("=" * 50)

    verifier = Verifier(did_registry, revocation_registry)
    print("✅CREAZIONE DEL VERIFIER AVVENUTA CON SUCCESSO")
    did_verifier = verifier.get_did()
    doc_verifier = verifier.get_did_document()
    print(f"did: {did_verifier}")
    print(f"did_document: {json.dumps(doc_verifier, indent=4)}")
    print("=" * 50)

    accreditation_authority = AccreditationAuthority(did_registry, revocation_registry)
    print("✅CREAZIONE DELL'ENTE DI ACCREDITAMENTO AVVENUTA CON SUCCESSO")
    did_accreditation = accreditation_authority.get_did()
    doc_accreditation = accreditation_authority.get_did_document()
    print(f"did: {did_accreditation}")
    print(f"did_document: {json.dumps(doc_accreditation, indent=4)}")
    print("=" * 50)

    print("Accreditamento in corso dell'Issuer...")
    certificate_issuer = accreditation_authority.generate_accreditation_certificate(did_issuer)
    print("✅CERTIFICAZIONE DELL'ISSUER AVVENUTA CON SUCCESSO")
    print(f"Certificate jwt:{certificate_issuer[:60]}...")
    print("=" * 50)

    print("Accreditamento in corso del Verifier...")
    certificate_verifier = accreditation_authority.generate_accreditation_certificate(did_verifier)
    print("✅CERTIFICAZIONE DEL VERIFIER AVVENUTA CON SUCCESSO")
    print(f"Certificate jwt:{certificate_verifier[:60]}...")
    print("=" * 50)

    did_registry.save_did(did_student, doc_student)
    did_registry.save_accredited_did(did_issuer, doc_issuer, certificate_issuer)
    did_registry.save_accredited_did(did_verifier, doc_verifier, certificate_verifier)
    did_registry.save_did(did_accreditation, doc_accreditation)

    print(f"DID in salvataggio. Transazioni in sospeso: {len(blockchain.pending_transactions)}")
    print("=" * 50)
    print("Mining del blocco per le registrazioni DID ...")
    blockchain.mine_pending_transactions(mining_reward_address="univer_miner_1")
    print("=" * 50)

    old_doc_issuer = doc_issuer
    old_doc_verifier = doc_verifier
    old_doc_accreditation = doc_accreditation
    old_doc_student = doc_student

    doc_issuer = did_registry.get_did_document(did_issuer)
    if doc_issuer == old_doc_issuer:
        print("✅SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER AVVENUTO CON SUCCESSO")
    else:
        print("SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER FALLITO")
    doc_student = did_registry.get_did_document(did_student)
    if doc_student == old_doc_student:
        print("✅SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER AVVENUTO CON SUCCESSO")
    else:
        print("SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER FALLITO")
    doc_verifier = did_registry.get_did_document(did_verifier)
    if doc_verifier == old_doc_verifier:
        print("✅SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER AVVENUTO CON SUCCESSO")
    else:
        print("SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER FALLITO")
    doc_accreditation = did_registry.get_did_document(did_accreditation)
    if doc_accreditation == old_doc_accreditation:
        print("✅SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER AVVENUTO CON SUCCESSO")
    else:
        print("SALVATAGGIO SULLA BLOCKCHAIN DEL DOCUMENT DELL'ISSUER FALLITO")
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
    verifiable_credential = issuer.create_verifiable_credential(did_student, did_accreditation, merkle_root)
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
    student.verify_credential(encrypted_data, did_registry, "")


if __name__ == "__main__":
    main()