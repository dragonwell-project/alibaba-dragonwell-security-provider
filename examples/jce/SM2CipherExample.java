import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.Cipher;
import org.conscrypt.SM2PrivateKey;
import org.conscrypt.SM2PrivateKeySpec;
import java.util.Base64;
import net.tongsuo.TongsuoProvider;

public class SM2CipherExample {
    static {
        // install tongsuo provider
        Security.addProvider(new TongsuoProvider());
    }

    public static void main(String[] args) throws Exception {
        byte[] mess = "example".getBytes();

        // SM2 cipher requires SM2 key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "Tongsuo_Security_Provider");
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        Cipher cipher = Cipher.getInstance("SM2", "Tongsuo_Security_Provider");
        // encrypt with public key
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(mess);
        byte[] ciphertext = cipher.doFinal();

        KeyFactory kf = KeyFactory.getInstance("SM2", "Tongsuo_Security_Provider");
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(((SM2PrivateKey) privateKey).getS());
        // decrypt with private key
        // keyfactory can convert KeySpec to Key
        cipher.init(Cipher.DECRYPT_MODE, kf.generatePrivate(privateKeySpec));
        cipher.update(ciphertext);
        byte[] decrypted = cipher.doFinal();

        // decrypted text should be identical to input
        System.out.println(Base64.getEncoder().encodeToString(mess));
        System.out.println(Base64.getEncoder().encodeToString(decrypted));
    }
}
