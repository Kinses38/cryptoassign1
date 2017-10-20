import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

import static javax.xml.crypto.dsig.Transform.BASE64;


public class Main
{
    public static void main (String [] args)
    {
        //https://xkcd.com/936/
        String plainTextPassword = "correctHorseBatteryStaple";
        String encryptionType = "AES/CBC/NoPadding";

        SymmEncrypt aes = new SymmEncrypt(plainTextPassword, encryptionType);
    }
}

class SymmEncrypt
{
    private static final Random RANDOM = new SecureRandom();
    private Cipher cipher;
    private byte [] iv, salt, key, passSalt, encryptedByte;
    private SecretKey aesKey;
    private IvParameterSpec ivRand;

    private File encryptedZip = new File("encrypted.zip");

    public SymmEncrypt(String pass, String encryptionType)
    {
        try
        {
            cipher = Cipher.getInstance(encryptionType);
            salt = generateSalt();
            iv = generateSalt();
            passSalt = concatPassSalt(pass, salt);
            key = hashPassSalt(passSalt);
            aesKey = new SecretKeySpec(key, 0, key.length, "AES");
            ivRand = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivRand);

            System.out.println("Salt: " + DatatypeConverter.printHexBinary(salt));
            System.out.println("Pass||Salt: " + DatatypeConverter.printHexBinary(passSalt));
            System.out.println("Hashed key: " + DatatypeConverter.printHexBinary(key));
            System.out.println(aesKey);
            //AES
            //TODO Read file in

            //TODO Break into blocks and pad

            //TODO Encrypt and write to file

            //RSA
            //TODO Modular Exp, yay

            //TODO Check/compare output

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private byte [] generateSalt()
    {
        byte [] salt = new byte[16];
        RANDOM.nextBytes(salt);

        return salt;
    }

    private byte [] concatPassSalt(String plaintext, byte [] salt)
    {
        byte [] passwordByte = plaintext.getBytes(StandardCharsets.UTF_8);
        byte [] unhashedKey = new byte [passwordByte.length + salt.length];

        System.arraycopy(passwordByte,0,unhashedKey,0, passwordByte.length);
        System.arraycopy(salt, 0, unhashedKey, passwordByte.length, salt.length);

        return unhashedKey;
    }

    private byte [] hashPassSalt(byte [] key)
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



}