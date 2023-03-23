import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;
import com.alibaba.dragonwell.security.DragonwellSecurityProvider;

public class SM3MessageDigestExample {
    static {
        // install dragonwell provider
        Security.addProvider(new DragonwellSecurityProvider());
    }

    public static void main(String[] args) throws Exception {
        byte[] mess = "example".getBytes();

        MessageDigest md = MessageDigest.getInstance("SM3", "Dragonwell_Security_Provider");
        // feed in mess(s) through update(s) before a final digest() call
        md.update(mess);
        byte[] res = md.digest();
        // show res in base64 encoding
        System.out.println(Base64.getEncoder().encodeToString(res));
    }
}
