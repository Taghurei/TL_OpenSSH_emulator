import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class Certificat {
	static private BigInteger seqnum = BigInteger.ZERO;
	public X509Certificate x509;
	Certificat(String nom, PaireClesRSA cle, int validityDays) {
	// Constructeur d’un certificat auto-signé avec
	// CN = nom, la clé publique contenu dans PaireClesRSA,
	// la durée de validité.
	}
	public boolean verifCertif (PublicKey pubkey) {
	// Vérification de la signature du certificat à l’aide
	// de la clé publique passée en argument.
		
	}
}
