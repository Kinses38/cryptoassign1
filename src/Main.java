import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.math.BigInteger;
import java.util.Random;

public class Main {
    private static final Random RANDOM = new SecureRandom();

    public static byte [] generateSalt()
    {
        byte [] salt = new byte[16];
        RANDOM.nextBytes(salt);

        String saltCheck = DatatypeConverter.printHexBinary(salt);
        System.out.println("Salt: " + saltCheck);

        return salt;
    }

    public static byte [] concatPassSalt(String plaintext, byte [] salt)
    {
        byte [] passwordByte = plaintext.getBytes(StandardCharsets.UTF_8);
        byte [] plainPassSalt = new byte [passwordByte.length + salt.length];

        System.arraycopy(passwordByte,0,plainPassSalt,0, passwordByte.length);
        System.arraycopy(salt, 0, plainPassSalt, passwordByte.length, salt.length);

        String plainPassSaltcheck = DatatypeConverter.printHexBinary(plainPassSalt);
        System.out.println("plainPass+salt: " + plainPassSaltcheck);

        return plainPassSalt;
    }

    public static void main (String [] args)
    {
        String plainTextPassword = "FirstAttempt";

        try
        {
            MessageDigest passwordDigest = MessageDigest.getInstance("SHA-256");
            byte [] digestArray = passwordDigest.digest(concatPassSalt(plainTextPassword, generateSalt()));
            String hexDigest = DatatypeConverter.printHexBinary(digestArray);
            System.out.println("Hashed Password: " + hexDigest);
        }
        catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }


     //sha-256 x 200

     //result stored as 256-bit aes key

     /*
      part 2

      */
    }
}
