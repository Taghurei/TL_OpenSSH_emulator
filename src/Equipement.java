import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.CertException;

public class Equipement {

	private PaireClesRSA maCle; // La paire de cle de l�equipement.
	private X509Certificate monCert; // Le certificat auto-signe.
	private String monNom; // Identite de l�equipement.
	private int monPort; // Le num�ro de port d�ecoute.

	Equipement(String nom, int port) {
		// Constructeur de l�equipement identifie par nom
		// et qui � �coutera � sur le port port.

		this.monNom = nom;
		this.monPort = port;
		this.maCle = new PaireClesRSA();
		Certificat certif = new Certificat(nom, maCle, 10);

		try {
			certif.verifCertif(maCle.Publique());
		} catch (CertException e) {
			System.err.println("Certificat non valide");
			e.printStackTrace();
		}
		try {
			this.monCert = certif.getCertificate();
		} catch (CertificateException e) {
			e.printStackTrace();
		}

	}

	public void affichage_da() {
		// Affichage de la liste des �quipements de DA.
		System.out.println("Affichage des Autorit�s de Certification");
	}

	public void affichage_ca() {
		// Affichage de la liste des �quipements de CA.
		System.out.println("Affichage des Autorit�s D�riv�es");
	}

	public void affichage() {
		// Affichage de l�ensemble des informations
		// de l��quipement.
		System.out.println("Je suis " + monNom + " et j'�coute sur le port " + monPort);
		System.out.println("Cl� publique: " + maCle.Publique());

		// Certif perso
		System.out.println("Mon certificat:");
		System.out.println(monCertif());

		// Certif connus
		this.affichage_ca();
		this.affichage_da();
	}

	public String monNom() {
		// Recuperation de l�identite de l��quipement.
		return this.monNom;
	}

	public PublicKey maClePub() {
		// Recuperation de la cl� publique de l��quipement.
		return this.maCle.Publique();
	}

	public X509Certificate monCertif() {
		// Recuperation du certificat auto-sign�.
		return this.monCert;
	}

	public void server() {
		System.out.println("Je suis un server");
	}

	public void client() {
		System.out.println("Je suis un client");
	}
}
