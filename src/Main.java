import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.math.BigInteger;
import java.util.Random;

public class Main {
    private static final Random RANDOM = new SecureRandom();

    private static byte [] generateSalt()
    {
        byte [] salt = new byte[16];
        RANDOM.nextBytes(salt);

        String saltCheck = DatatypeConverter.printHexBinary(salt);
        System.out.println("Salt: " + saltCheck);

        return salt;
    }

    private static byte [] concatPassSalt(String plaintext, byte [] salt)
    {
        byte [] passwordByte = plaintext.getBytes(StandardCharsets.UTF_8);
        byte [] unhashedKey = new byte [passwordByte.length + salt.length];

        System.arraycopy(passwordByte,0,unhashedKey,0, passwordByte.length);
        System.arraycopy(salt, 0, unhashedKey, passwordByte.length, salt.length);

        return unhashedKey;
    }

    private static byte [] hashPassSalt(byte [] key)
    {
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < 200; i++)
            {
                key = digest.digest(key);
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return key;
    }

    public static void main (String [] args)
    {
        String plainTextPassword = "FirstAttempt";

        byte [] digestArray = concatPassSalt(plainTextPassword, generateSalt());
        System.out.println("PreHashed: "  + DatatypeConverter.printHexBinary(digestArray));
        byte [] key = hashPassSalt(digestArray);
        System.out.println("Hashed Password: " + DatatypeConverter.printHexBinary(key));
    }
}
