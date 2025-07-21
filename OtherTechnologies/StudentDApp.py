from typing import Dict


class StudentDApp:
    def __init__(self):
        self.current_credential = None

    def store_credential(self, disclosed_attributes: dict, vc_jwt: str):
        self.current_credential = {
            "disclosed_attributes": disclosed_attributes,
            "vc_jwt": vc_jwt
        }
        print("✅ Credenziale salvata nella DApp dello studente")

    def get_credential(self):
        return self.current_credential

    def select_attributes(self) -> Dict[str, any]:
        if not self.current_credential:
            print("❌ Nessuna credenziale trovata.")
            return {}

        full_data = self.current_credential["disclosed_attributes"]

        selected = {"studentInfo": full_data.get("studentInfo", {})}
        print("✅ Blocco 'studentInfo' incluso automaticamente.")

        erasmus_info = full_data.get("erasmusInfo", {})

        selectable_options = {
            "1": ("erasmusStartDate", erasmus_info.get("erasmusStartDate")),
            "2": ("erasmusEndDate", erasmus_info.get("erasmusEndDate")),
            "3": ("learningAgreement.agreedCourses", erasmus_info.get("learningAgreement", {}).get("agreedCourses")),
            "4": ("languageCertificates", erasmus_info.get("languageCertificates")),
            "5": ("otherActivities", erasmus_info.get("otherActivities")),
        }

        print("\n📋 Attributi/blocchi disponibili per la selezione:")
        for k, (label, value) in selectable_options.items():
            preview = f"{value}"[:80] if value is not None else "N/A"
            print(f"{k}. {label}: {preview}")

        selection = input("\n🔢 Inserisci i numeri degli elementi da includere (separati da virgola): ")
        try:
            selected_indices = [s.strip() for s in selection.split(",")]
            for idx in selected_indices:
                if idx in selectable_options:
                    key_path, value = selectable_options[idx]
                    parts = key_path.split(".")
                    current = selected.setdefault("erasmusInfo", {})
                    for part in parts[:-1]:
                        current = current.setdefault(part, {})
                    current[parts[-1]] = value
            print("✅ Attributi selezionati correttamente.")
            return selected
        except Exception as e:
            print(f"❌ Errore nella selezione: {e}")
            return selected

