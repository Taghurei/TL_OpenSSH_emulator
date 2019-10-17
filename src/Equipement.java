
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
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

import org.bouncycastle.cert.CertException;

public class Equipement {

	private PaireClesRSA maCle; // La paire de cle de l’equipement.
	private X509Certificate monCert; // Le certificat auto-signe.
	private CertificatHolder monCertHolder;
	private String monNom; // Identite de l’equipement.
	private int monPort; // Le numéro de port d’ecoute.
	Set<String> listCA = new HashSet<String>();

	private Set<String> listDA;

	Equipement(String nom, int port) {
		// Constructeur de l’equipement identifie par nom
		// et qui « écoutera » sur le port port.

		this.monNom = nom;
		this.monPort = port;
		this.maCle = new PaireClesRSA();
		CertificatHolder certifHolder = new CertificatHolder(nom, maCle, 10);
		this.monCertHolder = certifHolder;

		try {
			certifHolder.verifCertif(maCle.Publique());
		} catch (CertException e) {
			System.err.println("Certificat non valide");
			e.printStackTrace();
		}
		try {
			this.monCert = certifHolder.getCertificate();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}

	public void affichage_da() {
		// Affichage de la liste des équipements de DA.
		System.out.println("Affichage des Autorités Dérivées");
		System.out.println(listDA);
	}

	public void affichage_ca() {
		// Affichage de la liste des équipements de CA.
		System.out.println("Affichage des Autorités de Certification");
		System.out.println(listCA);
	}

	public void affichage() {
		// Affichage de l’ensemble des informations
		// de l’équipement.
		System.out.println("Je suis " + this.monNom + " et j'écoute sur le port " + this.monPort);
		System.out.println("Clé publique: " + this.maCle.Publique());

		// Certif perso
		System.out.println("Mon certificat:");
		System.out.println(monCert());

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

	public X509Certificate monCert() {
		// Recuperation du certificat auto-signé.
		return this.monCert;
	}

	public void server() {
		// used later in server
		@SuppressWarnings("resource")
		Scanner scan = new Scanner(System.in);

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
			System.out.println("Je suis connecté");
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		System.out.println("J'ai reçu une connexion");
		// Creation des flux natifs et evolues
		try {
			NativeIn = NewServerSocket.getInputStream();
			ois = new ObjectInputStream(NativeIn);
			NativeOut = NewServerSocket.getOutputStream();
			oos = new ObjectOutputStream(NativeOut);
		} catch (IOException e) {
			// Gestion des exceptions
		}

		String nameClient = "";
		// Reception d’un String
		try {
			nameClient = (String) ois.readObject();
			System.out.println("le client suivant souhaite se connecter:" + nameClient);
		} catch (ClassNotFoundException | IOException e1) {
			e1.printStackTrace();
		}

		// Emission d’un String
		try {
			System.out.println(
					" J'envoie mon cert au format PEM \n qui juste un DER en base64 avec un header et un footer jolie");
			oos.writeObject(this.monCertHolder.cert2PEM());
			oos.flush();

			System.out.println("Et j'envoie mon nom ensuite");
			oos.writeObject(this.monNom);
			oos.flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		ConnexionClient: while (true) {
			System.out.println("On imagine ici que je n'ai pas le certificat (a implementer)");
			System.out.println("Voulez vous accepter la connexion entrante? (y/n)");
			String accept = scan.next();
			switch (accept) {
			case "y":
				try {
					oos.writeObject("connexion acceptée");
					oos.flush();
					try {
						String res = (String) ois.readObject();
						System.out.println("le client a donné la réponse suivante:" + res);
						if (res.equals("connexion acceptée")) {
							System.out.println("Nous avons tous les 2 accepté la connexion"
									+ " nous pouvons echanger nos certificats");
							listCA.add(nameClient);
						} else {
							System.out.println("le serveur a refusé la connexion");
						}
					} catch (ClassNotFoundException | IOException e1) {
						System.out.println("echec de connexion");
						e1.printStackTrace();
					}
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				// Cas ou l'utilisateur accepte la connexion
				break ConnexionClient;
			case "n":
				try {
					oos.writeObject("connexion refusée");
					oos.flush();
					System.out.println("J'ai refusé la connexion" + " nous n'echangeons pas nos certificats");
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				break ConnexionClient;
			default:
				System.out.println("Commande inconnue");
				break;
			}
		}

		// Fermeture des flux evolues et natifs
		try {
			ois.close();
			oos.close();
			NativeIn.close();
			NativeOut.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Fermeture de la connexion
		try {
			NewServerSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Arret du serveur
		try {
			serverSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void client(String ServerName, int ServerPort) {
		// used later in client
		@SuppressWarnings("resource")
		Scanner scan = new Scanner(System.in);
		System.out.println("Je me connecte en tant que client à " + ServerName + " port " + ServerPort);
		Socket clientSocket = null;
		InputStream NativeIn = null;
		ObjectInputStream ois = null;
		OutputStream NativeOut = null;
		ObjectOutputStream oos = null;

		// Creation de socket (TCP)
		try {
			clientSocket = new Socket(ServerName, ServerPort);
			System.out.println("Je suis connecté");
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		System.out.println("Tentative de connexion...");

		// Creation des flux natifs et evolues
		try {
			NativeOut = clientSocket.getOutputStream();
			oos = new ObjectOutputStream(NativeOut);
			NativeIn = clientSocket.getInputStream();
			ois = new ObjectInputStream(NativeIn);
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		// Emission d’un String
		try {
			oos.writeObject(this.monNom);
			oos.flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		// Reception de Strings
		String certPEMReceived = null;
		String nameReceived = null;
		try {
			certPEMReceived = (String) ois.readObject();
			nameReceived = (String) ois.readObject();
		} catch (ClassNotFoundException | IOException e2) {
			e2.printStackTrace();
		}

		CertificatHolder certHold;
		try {
			certHold = new CertificatHolder(certPEMReceived);
			System.out.println("Je suis capable d'afficher le certificat que j'ai reçu");
			System.out.println(certHold.getCertificate());
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		System.out.println("le serveur est :" + nameReceived);// nom du serveur

		ConnexionServer: while (true) {
			System.out.println("On imagine ici que je n'ai pas le certificat (a implementer)");
			System.out.println("Voulez vous confirmer la connexion au serveur? (y/n)");
			String accept = scan.next();
			switch (accept) {
			case "y":
				try {
					oos.writeObject("connexion acceptée");
					oos.flush();
					try {
						String resAnswer = (String) ois.readObject();
						System.out.println("le serveur a donné la réponse suivante:" + resAnswer);
						if (resAnswer.equals("connexion acceptée")) {
							System.out.println("Nous avons tous les 2 accepté la connexion"
									+ " nous pouvons echanger nos certificats");
						}
						listCA.add(ServerName);
					} catch (ClassNotFoundException | IOException e1) {

						e1.printStackTrace();
					}
				} catch (IOException e1) {

					e1.printStackTrace();
				}
				// Cas ou l'utilisateur accepte la connexion
				break ConnexionServer;
			case "n":
				try {
					oos.writeObject("connexion refusée");
					oos.flush();
					System.out.println("J'ai refusé la connexion" + " nous n'echangeons pas nos certificats");
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				break ConnexionServer;
			default:
				System.out.println("Commande inconnue");
				break;
			}
		}

		// Fermeture des flux evolues et natifs
		try {
			ois.close();
			oos.close();
			NativeIn.close();
			NativeOut.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Fermeture de la connexion
		try {
			clientSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
