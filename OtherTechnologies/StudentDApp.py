import json
from typing import Dict


class StudentDApp:
    """Classe che simula la DApp per lo studente"""

    def __init__(self):
        self.current_credential = None

    def store_credential(self, disclosed_attributes: dict, vc_jwt: str):
        """
        Salvataggio nella DApp delle informazioni ricevute dallo studente
        :param disclosed_attributes: Attributi in chiaro ricevuti
        :param vc_jwt: verifiable credential in jwt ricevuta
        """
        self.current_credential = {
            "disclosed_attributes": disclosed_attributes,
            "vc_jwt": vc_jwt
        }
        print("✅ Credenziale salvata nella DApp dello studente")

    def get_credential(self):
        """
        Metodo per ottenere la credenziale correntemente salvata
        :return: la credenziale corrente
        """
        return self.current_credential

    @staticmethod
    def authenticate_user(max_attempts: int = 3) -> bool:
        """
        Metodo per simulare l'autenticazione dello studente
        :param max_attempts: numero massimo di tentativi concessi
        :return: true se il processo è andato a buon fine, altrimenti false
        """
        #Prova ad aprire il file in cui si trovano l'email e la password salvati
        try:
            with open("Utils/credential.json", "r") as f:
                credentials = json.load(f) #Carica il contenuto json
        except FileNotFoundError:
            print("❌File delle credenziali non trovato.")
            return False

        #Itera sui tentativi permesssi
        for attempt in range(1, max_attempts + 1):
            print(f"\nTentativo di accesso ({attempt}/{max_attempts})")
            email_input = input("Email: ") #Chiede l'email
            password_input = input("Password: ") #chiede la password

            #Verifica che la password e l'email inseriti sono corretti
            if email_input == credentials.get("email") and password_input == credentials.get("password"):
                print("✅Accesso effettuato con successo.\n")
                return True
            else:
                print(f"❌ Credenziali non valide.")

        print("❌Numero massimo di tentativi raggiunto. Accesso negato.")
        return False

    def select_attributes(self) -> Dict[str, any]:
        """
        Metodo per simulare la selezione degli attributi tramite la DApp
        :return: gli attributi selezionati dallo studente
        """
        #Verifico che ci sia una credenziale corrente
        if not self.current_credential:
            print("❌ Nessuna credenziale trovata.")
            return {}

        #Ottengo i dati riguardanti la credenziale corrente
        full_data = self.current_credential["disclosed_attributes"]

        #Includo automaticamente le informazioni riguardanti lo studente
        selected = {"studentInfo": full_data.get("studentInfo", {})}
        print("✅ Blocco 'studentInfo' incluso automaticamente.")

        #Ottengo i dati riguardanti l'erasmus
        erasmus_info = full_data.get("erasmusInfo", {})

        #Creo un dizionario vuoto di possibili elementi selezionabili
        selectable_options = {}

        #Imposto il primo valore opzionabile
        option_num = 1

        # Costruzione opzioni
        for key, value in erasmus_info.items():
            if isinstance(value, dict): #Caso dizionario
                #Itera attraverso le coppie chiave valore presenti nel dizionario
                for subkey, subval in value.items():
                    #Crea etichetta combinata
                    option_label = f"{key}.{subkey}"

                    # Aggiunge a opzioni selezionabili
                    selectable_options[str(option_num)] = (option_label, subval)

                    #Aumenta il numero di opzioni selezionabili
                    option_num += 1
            elif isinstance(value, list): #Caso lista
                # Per ogni elemento nella lista, opzione con indice
                for i, item in enumerate(value):
                    #Crea etichetta personalizzata
                    option_label = f"{key}[{i}]"

                    # Aggiunge a opzioni selezionabili
                    selectable_options[str(option_num)] = (option_label, item)

                    # Aumenta il numero di opzioni selezionabili
                    option_num += 1
            else: #Caso valore atomico
                #Aggiunge a opzioni selezionabili
                selectable_options[str(option_num)] = (key, value)

                # Aumenta il numero di opzioni selezionabili
                option_num += 1

        # Stampa opzioni
        print("\n📋 Attributi/blocchi disponibili per la selezione:")
        for k, (label, value) in selectable_options.items():
            preview = f"{value}"[:80] if value is not None else "N/A"
            print(f"{k}. {label}: {preview}")

        #Continua a chiedere la selezione fino a che non vengono forniti input validi
        while True:
            selection = input("\n🔢 Inserisci i numeri degli elementi da includere (separati da virgola): ").strip()

            #Splitta la stringa fornita tramite il separatore ","
            selected_indices = [s.strip() for s in selection.split(",")]

            #Controlla se tutti i valori forniti sono opzioni selezionabili
            #Se lo sono esce dal ciclo, altrimenti mostra un messaggio di errore e richiede l'input
            if all(idx in selectable_options for idx in selected_indices):
                break
            else:
                print("❌ Input non valido, assicurati di inserire solo numeri tra le opzioni disponibili.")

        #Itera su ogni numero fornito dallo studente
        for idx in selected_indices:
            #Recupera chiave e valore dell'attributo selezionato
            key_path, value = selectable_options[idx]

            #Trasforma la chiave in una lista di parti
            parts = key_path.replace(']', '').replace('[', '.').split('.')

            #Imposta il riferimento ad erasmus info
            current = selected.setdefault("erasmusInfo", {})

            #Itera nelle diverse parti della chiave
            for part in parts[:-1]:
                #Caso indice numerico di lista
                if part.isdigit():
                    #Converte in intero
                    part = int(part)

                    #Controlla se è una lista
                    if not isinstance(current, list):
                        #Se non lo è la crea
                        current_list = []

                        #Recupera la chiave precedente
                        current_key = parts[parts.index(str(part)) - 1]

                        #Associa la selezione con questa lista
                        selected["erasmusInfo"][current_key] = current_list
                        current = current_list

                    #Allunga la lista fino ad arrivare all'indice part
                    while len(current) <= part:
                        current.append({})
                    current = current[part]
                else: #Caso dizionario
                    current = current.setdefault(part, {})

            #Prende l'ultima parte del percorso
            last_part = parts[-1]

            #Caso indice numerico di lista
            if last_part.isdigit():

                #Converte in intero
                last_part = int(last_part)

                #Controlla se è una lista
                if not isinstance(current, list):
                    #Se non lo è la crea
                    current_list = []

                    #Recupera la chiave precedente
                    current_key = parts[-2]

                    #Asoocia la selezione con la lista
                    selected["erasmusInfo"][current_key] = current_list
                    current = current_list

                #Allunga la lista fino all'indice numerico
                while len(current) <= last_part:
                    current.append({})
                current[last_part] = value
            else:
                current[last_part] = value

        print("✅ Attributi selezionati correttamente.")
        return selected