import java.security.PublicKey;

public class Equipement {

	private PaireClesRSA maCle; // La paire de cle de l’equipement.
	private Certificat monCert; // Le certificat auto-signe.
	private String monNom; // Identite de l’equipement.
	private int monPort; // Le numéro de port d’ecoute.

	Equipement(String nom, int port) throws Exception { // maybe specify which
														// exception
		// Constructeur de l’equipement identifie par nom
		// et qui « écoutera » sur le port port.
	}

	public void affichage_da() {
		// Affichage de la liste des équipements de DA.
	}

	public void affichage_ca() {
		// Affichage de la liste des équipements de CA.
	}

	public void affichage() {
		// Affichage de l’ensemble des informations
		// de l’équipement.
	}

	public String monNom() {
		// Recuperation de l’identite de l’équipement.
		return monNom;
	}

	public PublicKey maClePub() {
		// Recuperation de la clé publique de l’équipement.
		return maCle.Publique();
	}

	public Certificat monCertif() {
		// Recuperation du certificat auto-signé.
		return monCert;
	}
}
