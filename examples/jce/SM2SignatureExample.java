import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import net.tongsuo.TongsuoProvider;

public class SM2SignatureExample {
    static {
        // install tongsuo provider
        Security.addProvider(new TongsuoProvider());
    }

    public static void main(String[] args) throws Exception {
        byte[] mess = "example".getBytes();

        // SM3withSM2 requires SM2 key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "Tongsuo_Security_Provider");
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        Signature sig = Signature.getInstance("SM3withSM2", "Tongsuo_Security_Provider");
        // sign using private key
        sig.initSign(privateKey);
        // feed in mess(s)
        sig.update(mess);
        // genereate signatrue
        byte[] signature = sig.sign();

        // verify using public key
        sig.initVerify(publicKey);
        // same mess(s) as in signing procedure
        sig.update(mess);
        // return true if signature is genuine
        System.out.println(sig.verify(signature));
    }
}
