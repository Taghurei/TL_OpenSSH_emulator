
import java.util.Scanner;

public class Main {

	public static void main(String[] args) {

		// user inputs
		Scanner scan = new Scanner(System.in);
		System.out.println("Nom de l'équipement:");
		String name = scan.next();
		System.out.println("Port de l'équipement:");
		int port = scan.nextInt();
		scan.close();
		
		// create one equipement
		Equipement equipement = new Equipement(name, port);
		equipement.affichage();
	}

}
