import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PaireClesRSA {
	private KeyPair key;
	
	PaireClesRSA() {
	// Constructeur : g�n�ration d�une paire de cl� RSA.
	}
	public PublicKey Publique() {
		return key.getPublic();
	}
	public PrivateKey Privee() {
		return key.getPrivate();
	}
}
