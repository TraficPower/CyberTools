import customtkinter as ctk
import subprocess


class CyberToolsApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberToolsApp")
        self.geometry("1000x700")

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (PageAccueil, OutilsNmap, OutilsHydra, OutilsMetasploit):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.afficher_page("PageAccueil")

    def afficher_page(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


class PageAccueil(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.creer_widgets()

    def creer_widgets(self):
        label = ctk.CTkLabel(self, text="Page d'accueil")
        label.pack(side="top", fill="x", pady=10)

        button1 = ctk.CTkButton(self, text="Outils Nmap", command=lambda: self.controller.afficher_page("OutilsNmap"))
        button1.pack(fill="x", padx=20, pady=5)

        button2 = ctk.CTkButton(self, text="Outils Hydra", command=lambda: self.controller.afficher_page("OutilsHydra"))
        button2.pack(fill="x", padx=20, pady=5)

        button3 = ctk.CTkButton(self, text="Outils Metasploit",
                                command=lambda: self.controller.afficher_page("OutilsMetasploit"))
        button3.pack(fill="x", padx=20, pady=5)

        BlocCLI(self).pack(fill="both", expand=True, pady=20)


class OutilsNmap(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.creer_widgets()

    def creer_widgets(self):
        label = ctk.CTkLabel(self, text="Outils Nmap")
        label.pack(side="top", fill="x", pady=10)

        button = ctk.CTkButton(self, text="Retour à la Page d'accueil",
                               command=lambda: self.controller.afficher_page("PageAccueil"))
        button.pack(fill="x", padx=20, pady=5)

        tool_button_texts = [
            ("Scan de Réseau", self.scan_reseau),
            ("Scan de Services Rapide", self.scan_service_rapide),
            ("Scan de Services Complet", self.scan_service_complet),
            ("Scan de Version des Services", self.scan_service_version)
        ]

        for text, cmd in tool_button_texts:
            btn = ctk.CTkButton(self, text=text, command=cmd)
            btn.pack(fill="x", padx=10, pady=5)

        BlocCLI(self).pack(fill="both", expand=True, pady=20)

    def scan_reseau(self):
        self.executer_commande_outil("nmap -sn 192.168.1.0/24")

    def scan_service_rapide(self):
        self.executer_commande_outil("nmap -F 192.168.1.1")

    def scan_service_complet(self):
        self.executer_commande_outil("nmap -sS -p- 192.168.1.1")

    def scan_service_version(self):
        self.executer_commande_outil("nmap -sV 192.168.1.1")

    def executer_commande_outil(self, commande):
        # Définir l'appel du sous-processus externe
        BlocCLI(self).executer_commande(commande)


class OutilsHydra(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.creer_widgets()

    def creer_widgets(self):
        label = ctk.CTkLabel(self, text="Outils Hydra")
        label.pack(side="top", fill="x", pady=10)

        button = ctk.CTkButton(self, text="Retour à la Page d'accueil",
                               command=lambda: self.controller.afficher_page("PageAccueil"))
        button.pack(fill="x", padx=20, pady=5)

        tool_button_texts = [
            ("Brute Force Service", self.brute_force_service),
            ("Brute Force Machine", self.brute_force_machine)
        ]

        for text, cmd in tool_button_texts:
            btn = ctk.CTkButton(self, text=text, command=cmd)
            btn.pack(fill="x", padx=10, pady=5)

        BlocCLI(self).pack(fill="both", expand=True, pady=20)

    def brute_force_service(self):
        self.executer_commande_outil("hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1")

    def brute_force_machine(self):
        self.executer_commande_outil(
            "hydra -L /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh")

    def executer_commande_outil(self, commande):
        BlocCLI(self).executer_commande(commande)


class OutilsMetasploit(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.creer_widgets()

    def creer_widgets(self):
        label = ctk.CTkLabel(self, text="Outils Metasploit")
        label.pack(side="top", fill="x", pady=10)

        button = ctk.CTkButton(self, text="Retour à la Page d'accueil",
                               command=lambda: self.controller.afficher_page("PageAccueil"))
        button.pack(fill="x", padx=20, pady=5)

        tool_button_texts = [
            ("Recherche Payload", self.recherche_payload)
        ]

        for text, cmd in tool_button_texts:
            btn = ctk.CTkButton(self, text=text, command=cmd)
            btn.pack(fill="x", padx=10, pady=5)

        BlocCLI(self).pack(fill="both", expand=True, pady=20)

    def recherche_payload(self):
        self.executer_commande_outil("msfvenom -l payloads")

    def executer_commande_outil(self, commande):
        BlocCLI(self).executer_commande(commande)


class BlocCLI(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.creer_widgets()

    def creer_widgets(self):
        self.saisie = ctk.CTkEntry(self, placeholder_text="Tapez une commande")
        self.saisie.pack(side="top", fill="x", padx=20, pady=10, expand=True)

        self.bouton_exec = ctk.CTkButton(self, text="Exécuter", command=self.executer_commande)
        self.bouton_exec.pack(side="top", padx=20, pady=10)

        self.sortie = ctk.CTkTextbox(self, height=200)  # Hauteur réduite pour CLI
        self.sortie.pack(fill="both", padx=20, pady=10, expand=True)

        self.bind('<Return>', self.executer_commande)

    def executer_commande(self, commande=None):
        if commande is None:
            commande = self.saisie.get()
        self.saisie.delete(0, ctk.END)
        self.sortie.delete("0.0", ctk.END)

        try:
            result = subprocess.check_output(commande, shell=True, stderr=subprocess.STDOUT, text=True)
            self.sortie.insert(ctk.END, result)
        except subprocess.CalledProcessError as e:
            self.sortie.insert(ctk.END, e.output)


if __name__ == "__main__":
    app = CyberToolsApp()
    app.mainloop()
