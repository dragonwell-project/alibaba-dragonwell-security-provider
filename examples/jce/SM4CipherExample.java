import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import com.alibaba.dragonwell.security.DragonwellSecurityProvider;

public class SM4CipherExample {
    static {
        // install tongsuo provider
        Security.addProvider(new DragonwellSecurityProvider());
    }

    public static void main(String[] args) throws Exception {
        byte[] mess = "example".getBytes();
        byte[] aad = "aad".getBytes();
        SecureRandom random = new SecureRandom();

        // algorithm/mode/padding
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", "Dragonwell_Security_Provider");
        byte[] key = new byte[16];
        random.nextBytes(key);
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        SecretKeySpec secretKey =  new SecretKeySpec(key, "SM4");
        // tagLen in bits
        GCMParameterSpec params = new GCMParameterSpec(96, iv);
        // init cipher in encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
        // multiple update(s) and a doFinal()
        // tag is appended in aead mode
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(mess);

        // init cipher in decryption mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        // same aad as in encryption
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);

        // decrypted text should be identical to input
        System.out.println(Base64.getEncoder().encodeToString(mess));
        System.out.println(Base64.getEncoder().encodeToString(decrypted));
    }
}
