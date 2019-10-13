import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PaireClesRSA {
	private KeyPair key;
	
	PaireClesRSA() {
	// Constructeur : génération d’une paire de clé RSA.
	}
	public PublicKey Publique() {
		return key.getPublic();
	}
	public PrivateKey Privee() {
		return key.getPrivate();
	}
}
