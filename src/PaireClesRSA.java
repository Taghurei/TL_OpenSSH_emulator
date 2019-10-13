import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class PaireClesRSA {
	private KeyPair key;

	PaireClesRSA() {
		// Constructeur : génération d’une paire de clé RSA.

		// On va mettre un peu d'alea :
		SecureRandom rand = new SecureRandom();
		// On initialise la structure pour la generation de cle :
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			// On definit la taille de cle :
			kpg.initialize(512, rand);
			// On genere la paire de cle :
			KeyPair key = kpg.generateKeyPair();

			this.key = key;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	public PublicKey Publique() {
		return key.getPublic();
	}

	public PrivateKey Privee() {
		return key.getPrivate();
	}
}
