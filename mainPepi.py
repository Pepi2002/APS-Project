import json

from ActorsPepi.AccreditationAuthority import AccreditationAuthority
from ActorsPepi.Issuer import Issuer
from ActorsPepi.Student import Student
from ActorsPepi.Verifier import Verifier
from BlockchainPepi.DIDRegistry import DIDRegistry
from BlockchainPepi.RevocationRegistry import RevocationRegistry
from BlockchainPepi.SimulatedBlockchain import SimulatedBlockchain
from OtherTechnologiesPepi.MerkleTree import MerkleTree
from Utils.CredentialUtils import CredentialUtils


def main():
    blockchain = SimulatedBlockchain()
    print("✅CREAZIONE DELLA BLOCKCHAIN SIMULATA AVVENUTA CON SUCCESSO")
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

    did_issuer = issuer.generate_did(did_registry)
    doc_issuer = did_registry.get_did_document(did_issuer)
    print("DOCUMENTO DID PER L'ISSUER:", json.dumps(doc_issuer, indent=4))
    print("=" * 50)
    did_student = student.generate_did(did_registry)
    doc_student = did_registry.get_did_document(did_student)
    print("DOCUMENTO DID PER LO STUDENTE:", json.dumps(doc_student, indent=4))
    print("=" * 50)
    did_verifier = verifier.generate_did(did_registry)
    doc_verifier = did_registry.get_did_document(did_verifier)
    print("DOCUMENTO DID PER IL VERIFIER:", json.dumps(doc_verifier, indent=4))
    print("=" * 50)
    did_authority = accreditation_authority.generate_did(did_registry)
    doc_authority = did_registry.get_did_document(did_authority)
    print("DOCUMENTO DID PER L'ENTE DI ACCREDITAMENTO:", json.dumps(doc_authority, indent=4))
    print("=" * 50)

    issuer.request_accreditation(accreditation_authority)
    if accreditation_authority.is_did_accredited(did_issuer):
        print("✅ACCREDITAMENTO DELL'ISSUER AVVENUTA CON SUCCESSO")
    else:
        print("ACCREDITAMENTO NON AVVENUTO")
    print("=" * 50)
    verifier.request_accreditation(accreditation_authority)
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
    student.verify_credential(encrypted_data, did_registry, "")


if __name__ == "__main__":
    main()