
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

	private PaireClesRSA maCle; // La paire de cle de l�equipement.
	private X509Certificate monCert; // Le certificat auto-signe.
	private CertificatHolder monCertHolder;
	private String monNom; // Identite de l�equipement.
	private int monPort; // Le num�ro de port d�ecoute.
	Set<X509Certificate> listCA = new HashSet<X509Certificate>();

	Set<X509Certificate> listDA = new HashSet<X509Certificate>();

	Equipement(String nom, int port) {
		// Constructeur de l�equipement identifie par nom
		// et qui � �coutera � sur le port port.

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
		// Affichage de la liste des �quipements de DA.
		System.out.println("Affichage des Autorit�s D�riv�es");
		System.out.println(listDA);
	}

	public void affichage_ca() {
		// Affichage de la liste des �quipements de CA.
		System.out.println("Affichage des Autorit�s de Certification");
		System.out.println(listCA);
	}

	public void affichage() {
		// Affichage de l�ensemble des informations
		// de l��quipement.
		System.out.println("Je suis " + this.monNom + " et j'�coute sur le port " + this.monPort);
		System.out.println("Cl� publique: " + this.maCle.Publique());

		// Certif perso
		System.out.println("Mon certificat:");
		System.out.println(monCert());

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

	public X509Certificate monCert() {
		// Recuperation du certificat auto-sign�.
		return this.monCert;
	}

	public void server() {
		// used later in server
		@SuppressWarnings("resource")
		Scanner scan = new Scanner(System.in);

		System.out.println("Je suis un serveur (" + this.monNom + ") qui �coute sur " + this.monPort);

		ServerSocket serverSocket = null;
		Socket NewServerSocket = null;
		InputStream NativeIn = null;
		ObjectInputStream ois = null;
		OutputStream NativeOut = null;
		ObjectOutputStream oos = null;
		String clientName = null;
		// Creation de socket (TCP)
		try {
			serverSocket = new ServerSocket(this.monPort);
		} catch (IOException e) {
			// Gestion des exceptions
		}

		// Attente de connextions
		try {
			NewServerSocket = serverSocket.accept();
			System.out.println("Je suis connect�");
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		System.out.println("J'ai re�u une connexion");
		// Creation des flux natifs et evolues
		try {
			NativeIn = NewServerSocket.getInputStream();
			ois = new ObjectInputStream(NativeIn);
			NativeOut = NewServerSocket.getOutputStream();
			oos = new ObjectOutputStream(NativeOut);
		} catch (IOException e) {
			// Gestion des exceptions
		}

		String certPEMClientReceived = null;
		CertificatHolder certHold = null;
		// Reception de Strings
		try {
			certPEMClientReceived = (String) ois.readObject();
		} catch (ClassNotFoundException | IOException e2) {
			e2.printStackTrace();
		}

		try {
			clientName = (String) ois.readObject();
		} catch (ClassNotFoundException | IOException e2) {
			e2.printStackTrace();
		}

		try {
			certHold = new CertificatHolder(certPEMClientReceived);
			System.out.println("Je suis capable d'afficher le certificat que j'ai re�u");
			System.out.println(certHold.getCertificate());
			System.out.println(certHold.getCertificate().getPublicKey());
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		CertificatHolder certifServerClient = null;
		try {
			certifServerClient = new CertificatHolder(this.monNom, clientName, this.maCle.Privee(),
					certHold.getCertificate().getPublicKey(), 10);
			System.out.println(certifServerClient.getCertificate());
		} catch (CertificateException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		try {
			oos.writeObject(certifServerClient.cert2PEM());
			oos.flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		// Emission d�un String
		try {
			System.out.println(
					" J'envoie mon cert au format PEM \n qui est juste un DER en base64 avec un header et un footer jolie");
			oos.writeObject(this.monCertHolder.cert2PEM());
			oos.flush();

			System.out.println("Et j'envoie mon nom ensuite");
			oos.writeObject(this.monNom);
			oos.flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		// je recois le certificat avec ma cle publique et je le verifie pour l'ajouter
		// a ma liste CA
		String certPEMClientServer = null;

		try {
			certPEMClientServer= (String) ois.readObject();
		} catch (ClassNotFoundException | IOException e2) {
			e2.printStackTrace();
		}
		CertificatHolder certHoldtoVerif = null;
		try {
			certHoldtoVerif = new CertificatHolder(certPEMClientServer);
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		try {
			try {
				if (certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
					System.out.println("certificat Serveur - Client verifi�");
					try {
						listCA.add(certHoldtoVerif.getCertificate());
					} catch (CertificateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} catch (CertException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (CertificateException e3) {
			// TODO Auto-generated catch block
			e3.printStackTrace();
		}

		ConnexionClient: while (true) {
			System.out.println("On imagine ici que je n'ai pas le certificat (a implementer)");
			System.out.println("Voulez vous accepter la connexion entrante? (y/n)");
			String accept = scan.next();
			switch (accept) {
			case "y":
				try {
					oos.writeObject("connexion accept�e");
					oos.flush();
					try {
						String res = (String) ois.readObject();
						System.out.println("le client a donn� la r�ponse suivante:" + res);
						if (res.equals("connexion accept�e")) {
							System.out.println("Nous avons tous les 2 accept� la connexion"
									+ " nous pouvons echanger nos certificats");
							try {
								listDA.add(certHold.getCertificate());
							} catch (CertificateException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} else {
							System.out.println("le serveur a refus� la connexion");
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
					oos.writeObject("connexion refus�e");
					oos.flush();
					System.out.println("J'ai refus� la connexion" + " nous n'echangeons pas nos certificats");
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

	/*
	 * separation serveur - client
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 */

	public void client(String ServerName, int ServerPort) {
		// used later in client
		@SuppressWarnings("resource")
		Scanner scan = new Scanner(System.in);
		System.out.println("Je me connecte en tant que client � " + ServerName + " port " + ServerPort);
		Socket clientSocket = null;
		InputStream NativeIn = null;
		ObjectInputStream ois = null;
		OutputStream NativeOut = null;
		ObjectOutputStream oos = null;

		// Creation de socket (TCP)
		try {
			clientSocket = new Socket(ServerName, ServerPort);
			System.out.println("Je suis connect�");
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

		// Emission d�un String
		try {
			oos.writeObject(this.monCertHolder.cert2PEM());
			oos.writeObject(this.monNom);
			oos.flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		// Reception de Strings
		String certPEMServerClient = null;
		String certPEMReceived = null;
		String nameReceived = null;
		try {
			certPEMServerClient = (String) ois.readObject();
			certPEMReceived = (String) ois.readObject();
			nameReceived = (String) ois.readObject();
		} catch (ClassNotFoundException | IOException e2) {
			e2.printStackTrace();
		}
		// on gere 2 certificats en parallele, le certificat autosigne du serveur
		// et celui cr�e avec la cle privee du serveur et notre cle publique qu'on doit
		// verifier
		CertificatHolder certHold = null;
		CertificatHolder certHoldtoVerif = null;
		try {
			certHold = new CertificatHolder(certPEMReceived);
			System.out.println("Je suis capable d'afficher le certificat que j'ai re�u");
			System.out.println(certHold.getCertificate());
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		try {
			certHoldtoVerif = new CertificatHolder(certPEMServerClient);
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		// si le certificat renvoy� par le serveur est valide on l'ajoute � notre liste
		// CA
		try {
			try {
				if (certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
					System.out.println("certificat Serveur - Client verifi�");
					try {
						listCA.add(certHoldtoVerif.getCertificate());
					} catch (CertificateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} catch (CertException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (CertificateException e3) {
			// TODO Auto-generated catch block
			e3.printStackTrace();
		}
		// On cr�e le certificat avec la cle publique du serveur et notre cle priv�e
		CertificatHolder certifClientServer = null;
		try {
			certifClientServer = new CertificatHolder(this.monNom, nameReceived, this.maCle.Privee(),
					certHold.getCertificate().getPublicKey(), 10);
			System.out.println(certifClientServer.getCertificate());
		} catch (CertificateException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		// Emission du certificat
		try {
			oos.writeObject(certifClientServer.cert2PEM());
			oos.flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}

		ConnexionServer: while (true) {
			System.out.println("On imagine ici que je n'ai pas le certificat (a implementer)");
			System.out.println("Voulez vous confirmer la connexion au serveur? (y/n)");
			String accept = scan.next();
			switch (accept) {
			case "y":
				try {
					oos.writeObject("connexion accept�e");
					oos.flush();
					try {
						String resAnswer = (String) ois.readObject();
						System.out.println("le serveur a donn� la r�ponse suivante:" + resAnswer);
						if (resAnswer.equals("connexion accept�e")) {
							System.out.println("Nous avons tous les 2 accept� la connexion"
									+ " nous pouvons echanger nos certificats");
						}
						try {
							listDA.add(certHold.getCertificate());
						} catch (CertificateException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
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
					oos.writeObject("connexion refus�e");
					oos.flush();
					System.out.println("J'ai refus� la connexion" + " nous n'echangeons pas nos certificats");
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
