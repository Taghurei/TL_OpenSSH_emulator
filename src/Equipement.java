
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.json.simple.JSONObject;

public class Equipement {
	private PaireClesRSA maCle; // La paire de cle de l’equipement.
	private X509Certificate monCert; // Le certificat auto-signe.
	private CertificatHolder monCertHolder;
	private String monNom; // Identite de l’equipement.
	private int monPort; // Le numéro de port d’ecoute.
	List<CertificatHolder> listCA = new ArrayList<CertificatHolder>(); // la liste des certificats CA
	List<CertificatHolder> listDA = new ArrayList<CertificatHolder>(); // la liste des certificats DA
	Map<String, PublicKey> mapKey = new HashMap<String, PublicKey>(); // un hashMap associant a un equipement sa cle
																		// publique
	List<String> mapDA = new ArrayList<String>(); // une liste donnant l'ensemble des couples Issuer - Subject de CA
	List<String> mapCA = new ArrayList<String>(); // une liste donnant l'ensemble des couples Issuer - Subject de DA

	Equipement(String nom, int port) throws CertificateException, CertException {
		// Constructeur de l’equipement identifie par nom
		// et qui « écoutera » sur le port port.
		this.monNom = nom;
		this.monPort = port;
		this.maCle = new PaireClesRSA();
		CertificatHolder certifHolder = new CertificatHolder(nom, maCle, 10);
		this.monCertHolder = certifHolder;
		certifHolder.verifCertif(maCle.Publique());
		this.monCert = certifHolder.getCertificate();

	}

	public boolean testIfBelongs(CertificatHolder certTempo, List<String> mapDA, List<String> mapCA)
			throws CertificateException {
		Boolean alreadyBelongs = false;
		for (int i = 0; i < mapCA.size(); i++) {
			if (mapCA.get(i).split("issuer : ")[1].split("-")[0]
					.equals(certTempo.getCertificate().getIssuerDN().getName().split("=")[1])
					&& mapCA.get(i).split("subject : ")[1].split("-")[0]
							.equals(certTempo.getCertificate().getSubjectDN().getName().split("=")[1])) {
				alreadyBelongs = true;
			}
		}
		for (int i = 0; i < mapDA.size(); i++) {
			if (mapDA.get(i).split("issuer : ")[1].split("-")[0]
					.equals(certTempo.getCertificate().getIssuerDN().getName().split("=")[1])
					&& mapDA.get(i).split("subject : ")[1].split("-")[0]
							.equals(certTempo.getCertificate().getSubjectDN().getName().split("=")[1])) {
				alreadyBelongs = true;
			}
		}
		return alreadyBelongs;

	}

	public boolean testCanBeVerif(CertificatHolder certTempo, Map<String, PublicKey> mapKey)
			throws CertificateException {
		if (mapKey.containsKey(certTempo.getCertificate().getIssuerDN().getName().split("=")[1])) {
			return true;
		}
		return false;
	}

	public boolean testIfVerif(CertificatHolder certTempo, Map<String, PublicKey> mapKey)
			throws CertificateException, CertException {
		if (certTempo.verifCertif(mapKey.get(certTempo.getCertificate().getIssuerDN().getName().split("=")[1]))) {
			return true;
		}
		return false;
	}

	public boolean testIfAccept(String name, Map<String, PublicKey> mapKey, List<CertificatHolder> listCA,
			List<CertificatHolder> listDA) throws CertificateException, CertException {
		if (mapKey.containsKey(name)) {
			for (int i = 0; i < listCA.size(); i++) {
				if (listCA.get(i).getCertificate().getSubjectDN().getName().split("=")[1].equals(name)
						&& listCA.get(i).verifCertif(
								mapKey.get(listCA.get(i).getCertificate().getIssuerDN().getName().split("=")[1]))) {
					return true;
				}
			}
			for (int i = 0; i < listDA.size(); i++) {

				if (listDA.get(i).getCertificate().getSubjectDN().getName().split("=")[1].equals(name)
						&& listDA.get(i).verifCertif(
								mapKey.get(listDA.get(i).getCertificate().getIssuerDN().getName().split("=")[1]))) {
					return true;
				}
			}
		}
		return false;
	}

	public void affichage_da() throws CertificateException {
		// Affichage de la liste des équipements de DA.
		System.out.println("Affichage des Autorités Dérivées");
		System.out.println(mapDA);
		Iterator<CertificatHolder> itr = listDA.iterator();
		while (itr.hasNext()) {
			System.out.println(itr.next().getCertificate());
		}
	}

	public void affichage_ca() throws CertificateException {
		// Affichage de la liste des équipements de CA.
		System.out.println("Affichage des Autorités de Certification");
		System.out.println(mapCA);
		Iterator<CertificatHolder> itr = listCA.iterator();
		while (itr.hasNext()) {
			System.out.println(itr.next().getCertificate());
		}
	}

	public void affichage() throws CertificateException {
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

	public void server() throws IOException, ClassNotFoundException, CertificateException, CertException {
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
		String clientName = null;
		// Creation de socket (TCP)
		serverSocket = new ServerSocket(this.monPort);
		// Attente de connextions
		NewServerSocket = serverSocket.accept();
		System.out.println("Je suis connecté");
		System.out.println("J'ai reçu une connexion");
		// Creation des flux natifs et evolues
		NativeIn = NewServerSocket.getInputStream();
		ois = new ObjectInputStream(NativeIn);
		NativeOut = NewServerSocket.getOutputStream();
		oos = new ObjectOutputStream(NativeOut);
		String certPEMClientReceived = null;
		CertificatHolder certHold = null;
		// Reception de Strings
		certPEMClientReceived = (String) ois.readObject();

		clientName = (String) ois.readObject();
		certHold = new CertificatHolder(certPEMClientReceived);
		System.out.println("Je suis capable d'afficher le certificat que j'ai reçu");
		System.out.println(certHold.getCertificate());
		System.out.println(certHold.getCertificate().getPublicKey());

		CertificatHolder certifServerClient = null;
		certifServerClient = new CertificatHolder(this.monNom, clientName, this.maCle.Privee(),
				certHold.getCertificate().getPublicKey(), 10);
		System.out.println(certifServerClient.getCertificate());
		oos.writeObject(certifServerClient.cert2PEM());
		oos.flush();

		// Emission d’un String
		System.out.println(
				" J'envoie mon cert au format PEM \n qui est juste un DER en base64 avec un header et un footer jolie");
		oos.writeObject(this.monCertHolder.cert2PEM());
		oos.flush();

		System.out.println("Et j'envoie mon nom ensuite");
		oos.writeObject(this.monNom);
		oos.flush();
		// je recois le certificat avec ma cle publique et je le verifie pour l'ajouter
		// a ma liste CA
		String certPEMClientServer = null;

		certPEMClientServer = (String) ois.readObject();

		CertificatHolder certHoldtoVerif = null;
		certHoldtoVerif = new CertificatHolder(certPEMClientServer);

		ConnexionClient: while (true) {
			String accept = "";
			if (testIfAccept(clientName, mapKey, listCA, listDA)) {
				accept = "y";
			} else {
				System.out.println("Voulez vous accepter la connexion entrante? (y/n)");
				accept = scan.next();
			}
			switch (accept) {
			case "y":
				oos.writeObject("connexion acceptée");
				oos.flush();
				if (certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
					System.out.println("certificat Client - Serveur verifié");
					if (!testIfBelongs(certHoldtoVerif, mapCA, mapCA)
							&& certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
						listCA.add(certHoldtoVerif);
						mapKey.put(certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1],
								certHold.getCertificate().getPublicKey());
						mapKey.put(certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1],
								certHoldtoVerif.getCertificate().getPublicKey());
						mapCA.add("issuer : " + certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1]
								+ "- subject : "
								+ certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1]);
					}
				}
				String res = (String) ois.readObject();
				System.out.println("le client a donné la réponse suivante:" + res);
				if (res.equals("connexion acceptée")) {
					System.out.println(
							"Nous avons tous les 2 accepté la connexion" + " nous pouvons echanger nos certificats");
					ArrayList<CertificatHolder> certTemp = new ArrayList<CertificatHolder>();
					oos.writeObject(listCA.size() + listDA.size());
					Iterator<CertificatHolder> i = listCA.iterator();
					while (i.hasNext())
						oos.writeObject(i.next().cert2PEM());
					Iterator<CertificatHolder> j = listDA.iterator();
					while (j.hasNext())
						oos.writeObject(j.next().cert2PEM());
					oos.flush();

					int size = 0;
					size = (int) ois.readObject();
					if (size != 0) {
						for (int k = 0; k < size; k++) {
							certTemp.add(new CertificatHolder((String) ois.readObject()));
						}
					}
					System.out.println("******");
					while (certTemp.size() != 0) {
						Iterator<CertificatHolder> h = certTemp.iterator();
						CertificatHolder certReceived = null;
						while (h.hasNext() && certTemp.size() != 0) {
							certReceived = h.next();
							if (!testIfBelongs(certReceived, mapDA, mapCA)) {
								if (testCanBeVerif(certReceived, mapKey)) {
									if (testIfVerif(certReceived, mapKey)) {
										mapKey.put(certReceived.getCertificate().getSubjectDN().getName().split("=")[1],
												certReceived.getCertificate().getPublicKey());
										mapDA.add("issuer : "
												+ certReceived.getCertificate().getIssuerDN().getName().split("=")[1]
												+ "- subject : "
												+ certReceived.getCertificate().getSubjectDN().getName().split("=")[1]);
										certTemp.remove(certReceived);
										listDA.add(certReceived);
										System.out.println(listDA);
										System.out.println(mapDA);
										break;
									} else {
										certTemp.remove(certReceived);
										System.out.println("certificat invalid");
										break;
									}
								}
							} else {
								certTemp.remove(certReceived);
								System.out.println((certReceived.getCertificate().getIssuerDN().getName()
										+ certReceived.getCertificate().getSubjectDN().getName())
										+ " already belongs in DA");
								break;
							}
						}
					}
				} else {
					System.out.println("le serveur a refusé la connexion");
				}
				// Cas ou l'utilisateur accepte la connexion
				break ConnexionClient;
			case "n":
				oos.writeObject("connexion refusée");
				oos.flush();
				System.out.println("J'ai refusé la connexion" + " nous n'echangeons pas nos certificats");

				break ConnexionClient;
			default:
				System.out.println("Commande inconnue");
				break;
			}
		}

		// Fermeture des flux evolues et natifs
		ois.close();
		oos.close();
		NativeIn.close();
		NativeOut.close();
		// Fermeture de la connexion
		NewServerSocket.close();
		// Arret du serveur
		serverSocket.close();
	}

	public void client(String ServerName, int ServerPort)
			throws CertificateException, UnknownHostException, IOException, CertException, ClassNotFoundException {
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
		clientSocket = new Socket(ServerName, ServerPort);
		System.out.println("Je suis connecté");

		System.out.println("Tentative de connexion...");

		// Creation des flux natifs et evolues
		NativeOut = clientSocket.getOutputStream();
		oos = new ObjectOutputStream(NativeOut);
		NativeIn = clientSocket.getInputStream();
		ois = new ObjectInputStream(NativeIn);

		// Emission d’un String
		oos.writeObject(this.monCertHolder.cert2PEM());
		oos.writeObject(this.monNom);
		oos.flush();

		// Reception de Strings
		String certPEMServerClient = null;
		String certPEMReceived = null;
		String nameReceived = null;
		certPEMServerClient = (String) ois.readObject();
		certPEMReceived = (String) ois.readObject();
		nameReceived = (String) ois.readObject();
		// on gere 2 certificats en parallele, le certificat autosigne du serveur
		// et celui crée avec la cle privee du serveur et notre cle publique qu'on doit
		// verifier
		CertificatHolder certHold = null;
		CertificatHolder certHoldtoVerif = null;
		certHold = new CertificatHolder(certPEMReceived);
		System.out.println("Je suis capable d'afficher le certificat que j'ai reçu");
		System.out.println(certHold.getCertificate());
		certHoldtoVerif = new CertificatHolder(certPEMServerClient);
		// si le certificat renvoyé par le serveur est valide on l'ajoute à notre liste
		// CA

		// On crée le certificat avec la cle publique du serveur et notre cle privée
		CertificatHolder certifClientServer = null;
		certifClientServer = new CertificatHolder(this.monNom, nameReceived, this.maCle.Privee(),
				certHold.getCertificate().getPublicKey(), 10);
		System.out.println(certifClientServer.getCertificate());
		// Emission du certificat
		oos.writeObject(certifClientServer.cert2PEM());
		oos.flush();
		ConnexionServer: while (true) {
			String accept = "";
			if (testIfAccept(nameReceived, mapKey, listCA, listDA)) {
				accept = "y";
			} else {
				System.out.println("Voulez vous accepter la connexion entrante? (y/n)");
				accept = scan.next();
			}
			switch (accept) {
			case "y":
				oos.writeObject("connexion acceptée");
				if (certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
					System.out.println("certificat Serveur - Client verifié");
					if (!testIfBelongs(certHoldtoVerif, mapCA, mapCA)
							&& certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
						listCA.add(certHoldtoVerif);
						mapKey.put(certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1],
								certHold.getCertificate().getPublicKey());
						mapKey.put(certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1],
								certHoldtoVerif.getCertificate().getPublicKey());
						mapCA.add("issuer : " + certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1]
								+ "- subject : "
								+ certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1]);
					}
				}
				oos.flush();
				String resAnswer = (String) ois.readObject();
				System.out.println("le serveur a donné la réponse suivante:" + resAnswer);
				if (resAnswer.equals("connexion acceptée")) {
					System.out.println(
							"Nous avons tous les 2 accepté la connexion" + " nous pouvons echanger nos certificats");
				}
				ArrayList<CertificatHolder> certTemp = new ArrayList<CertificatHolder>();
				int size = 0;
				size = (int) ois.readObject();
				if (size != 0) {
					for (int i = 0; i < size; i++) {
						certTemp.add(new CertificatHolder((String) ois.readObject()));
					}
				}
				oos.writeObject(listCA.size() + listDA.size());
				Iterator<CertificatHolder> i = listCA.iterator();
				while (i.hasNext())
					oos.writeObject(i.next().cert2PEM());
				Iterator<CertificatHolder> j = listDA.iterator();
				while (j.hasNext())
					oos.writeObject(j.next().cert2PEM());
				oos.flush();
				while (certTemp.size() != 0) {
					System.out.println(certTemp.size());
					Iterator<CertificatHolder> h = certTemp.iterator();
					CertificatHolder certReceived = null;
					System.out.println(h.hasNext());
					while (h.hasNext() && certTemp.size() != 0) {
						certReceived = h.next();
						if (!testIfBelongs(certReceived, mapDA, mapCA)) {
							if (testCanBeVerif(certReceived, mapKey)) {
								if (testIfVerif(certReceived, mapKey)) {
									mapKey.put(certReceived.getCertificate().getSubjectDN().getName().split("=")[1],
											certReceived.getCertificate().getPublicKey());
									mapDA.add("issuer : "
											+ certReceived.getCertificate().getIssuerDN().getName().split("=")[1]
											+ "- subject : "
											+ certReceived.getCertificate().getSubjectDN().getName().split("=")[1]);
									certTemp.remove(certReceived);
									listDA.add(certReceived);
									System.out.println(listDA);
									System.out.println(mapDA);
									break;
								} else {
									certTemp.remove(certReceived);
									System.out.println("certificat invalid");
									break;
								}
							}
						} else {
							certTemp.remove(certReceived);
							System.out.println((certReceived.getCertificate().getIssuerDN().getName()
									+ certReceived.getCertificate().getSubjectDN().getName())
									+ " already belongs in DA");
							break;
						}
					}
				}
				System.out.println(mapDA);
				// Cas ou l'utilisateur accepte la connexion
				break ConnexionServer;
			case "n":
				oos.writeObject("connexion refusée");
				oos.flush();
				System.out.println("J'ai refusé la connexion" + " nous n'echangeons pas nos certificats");
				break ConnexionServer;
			default:
				System.out.println("Commande inconnue");
				break;
			}
		}

		// Fermeture des flux evolues et natifs
		ois.close();
		oos.close();
		NativeIn.close();
		NativeOut.close();
		// Fermeture de la connexion
		clientSocket.close();
	}

}
