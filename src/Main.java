
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {

		// user inputs
		Scanner scan = new Scanner(System.in);
		System.out.println("Nom de l'�quipement:");
		String name = scan.next();
		System.out.println("Port de l'�quipement:");
		int port = scan.nextInt();

		// create one equipement
		Equipement equipement = new Equipement(name, port);
		equipement.affichage();

		CLIInput: while (true) {
			System.out.println("\n" + equipement.monNom() + " >> ");
			String input = scan.next();
			switch (input) {
			case "q":
				System.out.println("Command line closed");
				break CLIInput;
			case "i":
				equipement.affichage();
				break;
			case "s":
				equipement.server();
				break;
			case "c":
				System.out.println("Nom du server et num�ro de port ?");
				String serverName = scan.next();
				int serverPort = scan.nextInt();
				equipement.client(serverName, serverPort);
				break;
			case "r": // Reseau domestique
				equipement.affichage_ca();
				equipement.affichage_da();
				break;

			case "help":
			case "h":
				System.out.println("q => Quitter");
				System.out.println("i => Informations de l'�quipement");
				System.out.println("s => Insertion en tant que server");
				System.out.println("c => Insertion en tant que client");
				System.out.println("r => Liste des �quipements sur le r�seau domestique");
				break;
			default:
				System.out.println("Commande inconnue");
				break;
			}
		}

		scan.close();
		System.out.println("Main loop finished");
	}

}
