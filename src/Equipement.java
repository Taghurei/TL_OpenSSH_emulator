
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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import org.bouncycastle.cert.CertException;

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
	List<String> listIssuerSubjectDA = new ArrayList<String>(); // une liste donnant l'ensemble des couples Issuer - Subject de CA
	List<String> listIssuerSubjectCA = new ArrayList<String>(); // une liste donnant l'ensemble des couples Issuer - Subject de DA

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

	public void verifyAllCertificate() throws CertificateException, CertException {
		// verify all the certificate and remove the outdated ones
		// update the issuer-subject list of the equipment
		for (int i = 0; i < listCA.size(); i++) {
			if (!listCA.get(i).verifCertif(mapKey.get(listCA.get(i).getCertificate().getIssuerDN().getName().split("=")[1]))) {
				listCA.remove(i);
				listIssuerSubjectCA.remove("issuer : "+ listCA.get(i).getCertificate().getIssuerDN().getName().split("=")[1]+"-subject : "+ listCA.get(i).getCertificate().getSubjectDN().getName().split("=")[1]);
			}
		}
		for (int i = 0; i < listDA.size(); i++) {
			if (!listDA.get(i).verifCertif(mapKey.get(listDA.get(i).getCertificate().getIssuerDN().getName().split("=")[1]))) {
				listDA.remove(i);
				listIssuerSubjectCA.remove("issuer : "+ listDA.get(i).getCertificate().getIssuerDN().getName().split("=")[1]+"-subject : "+ listDA.get(i).getCertificate().getSubjectDN().getName().split("=")[1]);

			}
		}

	}
	
	public boolean testIfBelongs(CertificatHolder certTempo, List<String> listIssuerSubjectDA, List<String> listIssuerSubjectCA)
			throws CertificateException {
		// verify if a certificate already belongs in the list of all the CA and DA of a given equipment
		Boolean alreadyBelongs = false;
		for (int i = 0; i < listIssuerSubjectCA.size(); i++) {
			if (listIssuerSubjectCA.get(i).split("issuer : ")[1].split("-")[0]
					.equals(certTempo.getCertificate().getIssuerDN().getName().split("=")[1])
					&& listIssuerSubjectCA.get(i).split("subject : ")[1].split("-")[0]
							.equals(certTempo.getCertificate().getSubjectDN().getName().split("=")[1])) {
				alreadyBelongs = true;
			}
		}
		for (int i = 0; i < listIssuerSubjectDA.size(); i++) {
			if (listIssuerSubjectDA.get(i).split("issuer : ")[1].split("-")[0]
					.equals(certTempo.getCertificate().getIssuerDN().getName().split("=")[1])
					&& listIssuerSubjectDA.get(i).split("subject : ")[1].split("-")[0]
							.equals(certTempo.getCertificate().getSubjectDN().getName().split("=")[1])) {
				alreadyBelongs = true;
			}
		}
		return alreadyBelongs;

	}

	public boolean doWeKnowEachOther(String myName, String clientName, Map<String, PublicKey> mapKey,
			List<CertificatHolder> listCA, List<CertificatHolder> listDA, ObjectInputStream ois, ObjectOutputStream oos)
			throws IOException, CertificateException, ClassNotFoundException, CertException {
		//Test to do at the beginning of a connexion to check whether or not the two equipment know each other
		// if they both know the other one, we don't need to test, if only one know the other, he send his 
		//chain of certificate and we verify all the chain to see if we can trust him
		boolean weKnowEachOther = false;
		if (testIfAccept(clientName, mapKey, listCA, listDA)) {
			oos.writeObject("IKnowYou");
			String serverAnswer = (String) ois.readObject();
			if (serverAnswer.equals("IKnowYou")) {
				weKnowEachOther = true;
			} else {
				List<CertificatHolder> listOfCertificate= new ArrayList<CertificatHolder>(listCA);
				listOfCertificate.addAll(listDA);
				List<String> listToSend = findChaineCertificate(myName, clientName, listIssuerSubjectCA, listIssuerSubjectDA);
				List<String> certificateToSend = new ArrayList<String>();
				int index=0;
				while(index<listToSend.size()-1) {
					for (int i = 0; i < listOfCertificate.size(); i++) {
						if(listOfCertificate.get(i).getCertificate().getIssuerDN().getName().split("=")[1]
								.equals(listToSend.get(index)) && listOfCertificate.get(i).getCertificate().getSubjectDN().getName().split("=")[1]
												.equals(listToSend.get(index+1))) {
							certificateToSend.add(listOfCertificate.get(i).cert2PEM());
							index++;
							break;
						}
					}
				}
				oos.writeObject(certificateToSend.size());
				Iterator<String> i = certificateToSend.iterator();
				while (i.hasNext())
					oos.writeObject(i.next());
				oos.flush();
				String serverNewAnswer = (String) ois.readObject();
				if (serverNewAnswer.equals("youKnowMe")) {
					weKnowEachOther = true;
				}
			}
		} else {
			oos.writeObject("IDontKnowYou");
			String serverAnswer = (String) ois.readObject();
			if (serverAnswer.equals("IKnowYou")) {
				ArrayList<CertificatHolder> certTemp = new ArrayList<CertificatHolder>();
				int size = 0;
				size = (int) ois.readObject();
				if (size != 0) {
					for (int k = 0; k < size; k++) {
						certTemp.add(new CertificatHolder((String) ois.readObject()));
					}
				}
				ArrayList<PublicKey> keyToCertify= new ArrayList<PublicKey>();
				keyToCertify.add(this.maCle.Publique());
				boolean youKnowMe = true;
				for (int i = 0; i < certTemp.size(); i++) {
					if(certTemp.get(i).verifCertif(keyToCertify.get(i))) {
						keyToCertify.add(certTemp.get(i).getCertificate().getPublicKey());
					}
					else {
						youKnowMe = false;
					}
				}
				if(youKnowMe) {
				oos.writeObject("youKnowMe");
				weKnowEachOther = true;
				}
				else {
				oos.writeObject("youDontKnowMe");
				weKnowEachOther = false;
				}
			}
		}
		return weKnowEachOther;
	}

	public List<String> findChaineCertificate(String myName, String clientName, List<String> listIssuerSubjectDA, List<String> listIssuerSubjectCA)
			throws CertificateException {
		// Bad algorithm to find the chain of certificate to trust another equipment - complexity o(n!) with n the number of certificate known by the equipment
		List<String> peopleInCertificate = new ArrayList<String>();
		List<String> listOfAllCertificate = new ArrayList<String>(listIssuerSubjectCA);
		listOfAllCertificate.addAll(listIssuerSubjectDA);
		peopleInCertificate.add(clientName);
		whileLoop: while (!peopleInCertificate.get(peopleInCertificate.size() - 1).equals(myName)) {
			for (int i = 0; i < listOfAllCertificate.size(); i++) {
				if (listOfAllCertificate.get(i).split("issuer : ")[1].split("-")[0]
						.equals(peopleInCertificate.get(peopleInCertificate.size() - 1))
						&& listOfAllCertificate.get(i).split("subject : ")[1].split("-")[0].equals(myName)) {
					peopleInCertificate.add(myName);
					break whileLoop;
				}
			}
			for (int i = 0; i < listOfAllCertificate.size(); i++) {
				if (listOfAllCertificate.get(i).split("issuer : ")[1].split("-")[0]
						.equals(peopleInCertificate.get(peopleInCertificate.size() - 1))) {
					peopleInCertificate.add(listOfAllCertificate.get(i).split("subject : ")[1].split("-")[0]);
					listOfAllCertificate.remove(i);
					break;
				}
			}
		}
		return peopleInCertificate;
	}

	public boolean testCanBeVerif(CertificatHolder certTempo, Map<String, PublicKey> mapKey)
			throws CertificateException {
		//test if we have the ability to verify if a certificate is valid or not
		if (mapKey.containsKey(certTempo.getCertificate().getIssuerDN().getName().split("=")[1])) {
			return true;
		}
		return false;
	}

	public boolean testIfVerif(CertificatHolder certTempo, Map<String, PublicKey> mapKey)
			throws CertificateException, CertException {
			//test if the certificate received is valid or not
		if (certTempo.verifCertif(mapKey.get(certTempo.getCertificate().getIssuerDN().getName().split("=")[1]))) {
			return true;
		}
		return false;
	}

	public boolean testIfAccept(String name, Map<String, PublicKey> mapKey, List<CertificatHolder> listCA,
			List<CertificatHolder> listDA) throws CertificateException, CertException {
		//test if the equipment need to find a chain of certificate or if he doesn't know the other equipment
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
		System.out.println(listIssuerSubjectDA);
		Iterator<CertificatHolder> itr = listDA.iterator();
		while (itr.hasNext()) {
			System.out.println(itr.next().getCertificate());
		}
	}

	public void affichage_ca() throws CertificateException {
		// Affichage de la liste des équipements de CA.
		System.out.println("Affichage des Autorités de Certification");
		System.out.println(listIssuerSubjectCA);
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
			verifyAllCertificate();
			boolean WeKnowEachOther = doWeKnowEachOther(this.monNom, clientName, mapKey, listCA, listDA, ois, oos);
			if (WeKnowEachOther) {
				accept = "y";
			} else {
				System.out.println("Voulez vous accepter la connexion entrante? (y/n)");
				accept = scan.next();
			}
			switch (accept) {
			case "y":
				if (certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
					System.out.println("certificat Client - Serveur verifié");
					if (!testIfBelongs(certHoldtoVerif, listIssuerSubjectCA, listIssuerSubjectCA)
							&& certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
						listCA.add(certHoldtoVerif);
						mapKey.put(certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1],
								certHold.getCertificate().getPublicKey());
						mapKey.put(certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1],
								certHoldtoVerif.getCertificate().getPublicKey());
						listIssuerSubjectCA.add("issuer : " + certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1]
								+ "-subject : "
								+ certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1]);
					}
				}
				boolean continueConnexion = false;
				if (WeKnowEachOther) {
					continueConnexion = true;
				} else {
					oos.writeObject("connexion acceptée");
					oos.flush();
					String res = (String) ois.readObject();
					System.out.println("le client a donné la réponse suivante:" + res);
					if (res.equals("connexion acceptée")) {
						continueConnexion = true;
					}
				}
				if (continueConnexion) {
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
					while (certTemp.size() != 0) {
						Iterator<CertificatHolder> h = certTemp.iterator();
						CertificatHolder certReceived = null;
						while (h.hasNext() && certTemp.size() != 0) {
							certReceived = h.next();
							if (!testIfBelongs(certReceived, listIssuerSubjectDA, listIssuerSubjectCA)) {
								if (testCanBeVerif(certReceived, mapKey)) {
									if (testIfVerif(certReceived, mapKey)) {
										mapKey.put(certReceived.getCertificate().getSubjectDN().getName().split("=")[1],
												certReceived.getCertificate().getPublicKey());
										listIssuerSubjectDA.add("issuer : "
												+ certReceived.getCertificate().getIssuerDN().getName().split("=")[1]
												+ "-subject : "
												+ certReceived.getCertificate().getSubjectDN().getName().split("=")[1]);
										certTemp.remove(certReceived);
										listDA.add(certReceived);
										break;
									} else {
										certTemp.remove(certReceived);
										System.out.println("certificat invalid");
										break;
									}
								}
							} else {
								certTemp.remove(certReceived);
								break;
							}
						}
					}
				} else {
					System.out.println("le client a refusé la connexion");
				}
				// Cas ou l'utilisateur accepte la connexion
				break ConnexionClient;
			case "n":
				oos.writeObject("connexion refusée");
				oos.flush();
				System.out.println("J'ai refusé la connexion nous n'echangeons pas nos certificats");

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
			verifyAllCertificate();
			boolean WeKnowEachOther = doWeKnowEachOther(this.monNom, nameReceived, mapKey, listCA, listDA, ois, oos);
			if (WeKnowEachOther) {
				accept = "y";
			} else {
				System.out.println("Voulez vous accepter la connexion entrante? (y/n)");
				accept = scan.next();
			}
			switch (accept) {
			case "y":
				if (certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
					System.out.println("certificat Client - Serveur verifié");
					if (!testIfBelongs(certHoldtoVerif, listIssuerSubjectCA, listIssuerSubjectCA)
							&& certHoldtoVerif.verifCertif(certHold.getCertificate().getPublicKey())) {
						listCA.add(certHoldtoVerif);
						mapKey.put(certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1],
								certHold.getCertificate().getPublicKey());
						mapKey.put(certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1],
								certHoldtoVerif.getCertificate().getPublicKey());
						listIssuerSubjectCA.add("issuer : " + certHoldtoVerif.getCertificate().getIssuerDN().getName().split("=")[1]
								+ "-subject : "
								+ certHoldtoVerif.getCertificate().getSubjectDN().getName().split("=")[1]);
					}
				}
				boolean continueConnexion = false;
				if (WeKnowEachOther) {
					continueConnexion = true;
				} else {
					oos.writeObject("connexion acceptée");
					oos.flush();
					String res = (String) ois.readObject();
					System.out.println("le client a donné la réponse suivante:" + res);
					if (res.equals("connexion acceptée")) {
						continueConnexion = true;
					}
				}
				if (continueConnexion) {
					System.out.println(
							"Nous avons tous les 2 accepté la connexion" + " nous pouvons echanger nos certificats");

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
							if (!testIfBelongs(certReceived, listIssuerSubjectDA, listIssuerSubjectCA)) {
								if (testCanBeVerif(certReceived, mapKey)) {
									if (testIfVerif(certReceived, mapKey)) {
										mapKey.put(certReceived.getCertificate().getSubjectDN().getName().split("=")[1],
												certReceived.getCertificate().getPublicKey());
										listIssuerSubjectDA.add("issuer : "
												+ certReceived.getCertificate().getIssuerDN().getName().split("=")[1]
												+ "-subject : "
												+ certReceived.getCertificate().getSubjectDN().getName().split("=")[1]);
										certTemp.remove(certReceived);
										listDA.add(certReceived);
										break;
									} else {
										certTemp.remove(certReceived);
										System.out.println("certificat invalid");
										break;
									}
								}
							} else {
								certTemp.remove(certReceived);
								break;
							}
						}
					}
				} else {
					System.out.println("Le serveur a refusé la connexion");
				}
				break ConnexionServer;

			case "n":
				oos.writeObject("connexion refusée");
				oos.flush();
				System.out.println("J'ai refusé la connexion nous n'echangeons pas nos certificats");
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
