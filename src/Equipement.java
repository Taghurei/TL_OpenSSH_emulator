import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.CertException;

public class Equipement {

	private PaireClesRSA maCle; // La paire de cle de l’equipement.
	private X509Certificate monCert; // Le certificat auto-signe.
	private String monNom; // Identite de l’equipement.
	private int monPort; // Le numéro de port d’ecoute.

	Equipement(String nom, int port) {
		// Constructeur de l’equipement identifie par nom
		// et qui « écoutera » sur le port port.

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
		// Affichage de la liste des équipements de DA.
		System.out.println("Affichage des Autorités Dérivées");
	}

	public void affichage_ca() {
		// Affichage de la liste des équipements de CA.
		System.out.println("Affichage des Autorités de Certification");
	}

	public void affichage() {
		// Affichage de l’ensemble des informations
		// de l’équipement.
		System.out.println("Je suis " + monNom + " et j'écoute sur le port " + monPort);
		System.out.println("Clé publique: " + maCle.Publique());

		// Certif perso
		System.out.println("Mon certificat:");
		System.out.println(monCertif());

		// Certif connus
		this.affichage_ca();
		this.affichage_da();
	}

	public String monNom() {
		// Recuperation de l’identite de l’équipement.
		return this.monNom;
	}

	public PublicKey maClePub() {
		// Recuperation de la clé publique de l’équipement.
		return this.maCle.Publique();
	}

	public X509Certificate monCertif() {
		// Recuperation du certificat auto-signé.
		return this.monCert;
	}

	public void server() {
		System.out.println("Je suis un serveur (" + this.monNom + ") qui écoute sur " + this.monPort);

		ServerSocket serverSocket = null;
		Socket NewServerSocket = null;
		InputStream NativeIn = null;
		ObjectInputStream ois = null;
		OutputStream NativeOut = null;
		ObjectOutputStream oos = null;

		// Creation de socket (TCP)
		try {
			serverSocket = new ServerSocket(this.monPort);
		} catch (IOException e) {
			// Gestion des exceptions
		}

		// Attente de connextions
		try {
			NewServerSocket = serverSocket.accept();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("Je suis connecté");

		// Creation des flux natifs et evolues
		try {
			NativeIn = NewServerSocket.getInputStream();
			ois = new ObjectInputStream(NativeIn);
			NativeOut = NewServerSocket.getOutputStream();
			oos = new ObjectOutputStream(NativeOut);
		} catch (IOException e) {
			// Gestion des exceptions
		}

		// Reception d’un String
		try {
			String res = (String) ois.readObject();
			System.out.println("Je reçois:" + res);
		} catch (ClassNotFoundException | IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Emission d’un String
		try {
			oos.writeObject("Au revoir");
			oos.flush();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Fermeture des flux evolues et natifs
		try {
			ois.close();
			oos.close();
			NativeIn.close();
			NativeOut.close();
		} catch (IOException e) {
			// Gestion des exceptions
		}

		// Fermeture de la connexion
		try {
			NewServerSocket.close();
		} catch (IOException e) {
			// Gestion des exceptions
		}

		// Arret du serveur
		try {
			serverSocket.close();
		} catch (IOException e) {
			// Gestion des exceptions
		}
	}

	public void client(String ServerName, int ServerPort) {
		System.out.println("Je me connecte en tant que client à " + ServerName + " port " + ServerPort);
		Socket clientSocket = null;
		InputStream NativeIn = null;
		ObjectInputStream ois = null;
		OutputStream NativeOut = null;
		ObjectOutputStream oos = null;

		// Creation de socket (TCP)
		try {
			clientSocket = new Socket(ServerName, ServerPort);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("Je suis connecté");

		// Creation des flux natifs et evolues
		try {
			NativeOut = clientSocket.getOutputStream();
			oos = new ObjectOutputStream(NativeOut);
			NativeIn = clientSocket.getInputStream();
			ois = new ObjectInputStream(NativeIn);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Emission d’un String
		try {
			oos.writeObject("Bonjour, je suis " + this.monNom);
			oos.flush();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Reception d’un String
		String res;
		try {
			res = (String) ois.readObject();
			System.out.println("Je reçois:" + res);
		} catch (ClassNotFoundException | IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Fermeture des flux evolues et natifs
		try {
			ois.close();
			oos.close();
			NativeIn.close();
			NativeOut.close();
		} catch (IOException e) {
			// Gestion des exceptions
		}

		// Fermeture de la connexion
		try {
			clientSocket.close();
		} catch (IOException e) {
			// Gestion des exceptions
		}
	}
}
