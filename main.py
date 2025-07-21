import json
import time

from Actors.AccreditationAuthority import AccreditationAuthority
from Actors.Issuer import Issuer
from Actors.Student import Student
from Actors.Verifier import Verifier
from Blockchain.DIDRegistry import DIDRegistry
from Blockchain.RevocationRegistry import RevocationRegistry
from Blockchain.Blockchain import Blockchain
from OtherTechnologies.MerkleTree import MerkleTree
from OtherTechnologies.StudentDApp import StudentDApp
from Utils.CredentialUtils import CredentialUtils


def main():

    blockchain = Blockchain()
    print("✅CREAZIONE DELLA BLOCKCHAIN SIMULATA (con PoW) AVVENUTA CON SUCCESSO")
    did_registry = DIDRegistry(blockchain)
    print("✅CREAZIONE DEL REGISTRO PER IL SALVATAGGIO DEI DID AVVENUTA CON SUCCESSO")
    revocation_registry = RevocationRegistry(blockchain)
    print("✅CREAZIONE DEL REGISTRO PER LA REVOCA AVVENUTA CON SUCCESSO")
    student_dapp = StudentDApp()
    print("✅CREAZIONE DELLA DAPP PER LO STUDENTE AVVENUTA CON SUCCESSO")
    print("=" * 50)

    issuer = Issuer(did_registry, revocation_registry)
    print("✅CREAZIONE DELL'ISSUER AVVENUTA CON SUCCESSO")
    did_issuer = issuer.get_did()
    doc_issuer = issuer.get_did_document()
    print(f"did: {did_issuer}")
    print(f"did_document: {json.dumps(doc_issuer, indent=4)}")
    print("=" * 50)

    student = Student(did_registry, revocation_registry, student_dapp)
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

    print("Simulazione accesso alla DApp da parte dello studente...")
    student_dapp.authenticate_user()
    print("✅AUTENTICAZIONE AVVENUTA CON SUCCESSO")

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

    # Misura la dimensione in byte della VC
    vc_size = len(verifiable_credential.encode('utf-8'))
    print(f"VC size (bytes): {vc_size}")

    message = {
        "vc": verifiable_credential,
        "data": data
    }

    message_json = json.dumps(message, indent=4)
    message_json = message_json.encode('utf-8')

    print("Trasmissione della credenziale allo Studente...")
    encrypted_data_vc = issuer.transmit(did_student, message_json)
    print("✅TRASMISSIONE VC AVVENUTA CON SUCCESSO")
    print("=" * 50)

    print("Processo di verifica in Corso...")
    start = time.time()
    result, disclosed_attributes, vc_jwt1 = student.verify_credential(encrypted_data_vc)
    end = time.time()
    print(f"VC verification latency (seconds): {end - start:.6f}")
    if result == False or disclosed_attributes is None or vc_jwt1 is None:
        print("Verifica non superata")
        return

    print(f"Informazioni ricevute: {json.dumps(disclosed_attributes, indent=4)}" )
    print(f"Verifiable Credential in jwt ricevuta: {vc_jwt1[:60]}...")
    print("=" * 50)

    print("Salvataggio nella DApp in corso...")
    student.store_credential_in_dapp(disclosed_attributes, vc_jwt1)
    print("✅SALVATAGGIO AVVENUTO CON SUCCESSO")
    print("=" * 50)

    print("Processo di Selezione in corso...")
    vp, disclosed_attributes= student.create_verifiable_presentation(vc_jwt1, did_verifier)
    print("✅SELEZIONE COMPLETATA CON SUCCESSO")
    print("=" * 50)

    # Misura la dimensione in byte della VP
    vp_size = len(vp.encode('utf-8'))
    print(f"VP size (bytes): {vp_size}")

    print(f"Informazioni selezionate: {json.dumps(disclosed_attributes, indent=4)}")
    print(f"Verifiable Presentation in jwt creata: {vp[:60]}...")
    print("=" * 50)

    print("Trasmissione della credenziale al Verifier...")
    encrypted_data_vp = student.transmit(did_verifier, vp)
    print("✅TRASMISSIONE VC AVVENUTA CON SUCCESSO")
    print("=" * 50)

    print("Processo di verifica in Corso...")
    start = time.time()
    result, disclosed_attributes, vp_jwt = verifier.verify_presentation(encrypted_data_vp)
    end = time.time()
    print(f"VP verification latency (seconds): {end - start:.6f}")
    if result == False or disclosed_attributes is None or vp_jwt is None:
        print("Verifica non superata")
        return
    print(f"Informazioni ricevute: {json.dumps(disclosed_attributes, indent=4)}")
    print(f"Verifiable Credential in jwt ricevuta: {vc_jwt1[:60]}...")
    print("=" * 50)

    print("Simulazione Replay Attack...")
    start = time.time()
    result, disclosed_attributes, vp_jwt = verifier.verify_presentation(encrypted_data_vp)
    end = time.time()
    print(f"VP verification latency (seconds): {end - start:.6f}")
    if result == False or disclosed_attributes is None or vp_jwt is None:
        print("Verifica non superata")
    print("=" * 50)

    print("Simulazione di Revoca...")
    issuer.revoke_credential(vc_jwt1)
    print(f"Revoca in esecuzione. Transazioni in sospeso: {len(blockchain.pending_transactions)}")
    print("=" * 50)
    print("Mining del blocco per le registrazioni DID ...")
    blockchain.mine_pending_transactions(mining_reward_address="univer_miner_1")
    print("=" * 50)

    print("Nuova Verifica della Verifiable Credential...")
    start = time.time()
    result, disclosed_attributes, vc_jwt2 = student.verify_credential(encrypted_data_vc)
    end = time.time()
    print(f"VC verification latency (seconds): {end - start:.6f}")
    if result == False or disclosed_attributes is None or vc_jwt2 is None:
        print("Verifica non superata")

    print("Nuova Verifica della Verifiable Presentation...")
    vp2, _ = student.create_verifiable_presentation(vc_jwt1, did_verifier)
    encrypted_data_vp2 = student.transmit(did_verifier, vp2)
    start = time.time()
    result, disclosed_attributes, vp_jwt = verifier.verify_presentation(encrypted_data_vp2)
    end = time.time()
    print(f"VP verification latency (seconds): {end - start:.6f}")
    if result == False or disclosed_attributes is None or vp_jwt is None:
        print("Verifica non superata")
    print("=" * 50)



if __name__ == "__main__":
    main()