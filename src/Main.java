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
        byte [] plainPassSalt = new byte [passwordByte.length + salt.length];

        System.arraycopy(passwordByte,0,plainPassSalt,0, passwordByte.length);
        System.arraycopy(salt, 0, plainPassSalt, passwordByte.length, salt.length);

        String plainPassSaltcheck = DatatypeConverter.printHexBinary(plainPassSalt);
        System.out.println("plainPass+salt: " + plainPassSaltcheck);

        return plainPassSalt;
    }

    private static byte [] hashPassSalt(byte [] passSalt)
    {
        byte [] key = new byte [passSalt.length];
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
        byte [] key = hashPassSalt(digestArray);

        String hexkey = DatatypeConverter.printHexBinary(key);
        System.out.println("Hashed Password: " + hexkey);
    }
}
