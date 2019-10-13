import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

public class Certificat {
	static private BigInteger seqnum = BigInteger.ZERO;
	public X509CertificateHolder x509holder;

	Certificat(String nom, PaireClesRSA cle, int validityDays) {
		// Constructeur d’un certificat auto-signé avec
		// CN = nom, la clé publique contenu dans PaireClesRSA,
		// la durée de validité.

		// Déclare le fournisseur BouncyCastke aka "BC"
		Security.addProvider(new BouncyCastleProvider());

		// On recupere la cle publique et la cle privee :
		PublicKey pubkey = cle.Publique();
		PrivateKey privkey = cle.Privee();
		// On cree la structure qui va contenir la signature :
		ContentSigner sigGen = null;
		try {
			sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privkey);
		} catch (OperatorCreationException e1) {
			e1.printStackTrace();
		}
		// On cree la structure qui contient la cle publique a certifier :
		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pubkey.getEncoded());
		// Le nom du proprietaire et du certifieur :
		// ici, les memes car auto-signe.
		X500Name issuer = new X500Name("CN=" + nom);
		X500Name subject = new X500Name("CN=" + nom);
		// Le numero de serie du futur certificat
		seqnum = seqnum.add(BigInteger.ONE);
		// Le certificat sera valide a partir d’hier ...
		Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		// ... et pour 10 jours
		Date endDate = new Date(System.currentTimeMillis() + validityDays * 24 * 60 * 60 * 1000);
		// On cree la structure qui va nous permettre de creer le certificat
		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(issuer, seqnum, startDate, endDate, subject,
				subPubKeyInfo);
		// On calcule la signature et on cree un certificate !
		X509CertificateHolder x509holder = v1CertGen.build(sigGen);

		this.x509holder = x509holder;
	}

	public X509Certificate getCertificate() throws CertificateException {
		return (new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509holder));
	}

	public boolean verifCertif(PublicKey pubKey) throws CertException {
		// Vérification de la signature du certificat à l’aide
		// de la clé publique passée en argument.
		// A partir de la cle publique de l’issuer, on construit
		// une structure pour verifier le certificat !
		ContentVerifierProvider verifier = null;
		try {
			verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(pubKey);
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// Verification d’un certificat !
		if (!x509holder.isSignatureValid(verifier)) {
			System.err.println("signature invalid");
			return false;
		} else {
			System.out.println("signature valid");
			return true;
		}
	}
}
