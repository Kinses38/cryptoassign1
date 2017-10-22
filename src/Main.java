import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;


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
    private byte [] iv, salt, key, passSalt, encryptedText, decryptedText;
    private SecretKey aesKey;
    private IvParameterSpec ivRand;

    private File sourceFile = new File ("src.zip");
    private File encryptedZip = new File("encrypted.zip");
    private File decryptedZip = new File("decrypted.zip");

    public SymmEncrypt(String pass, String encryptionType)
    {
        try
        {
            cipher = Cipher.getInstance(encryptionType);
            salt = generateSalt();
            iv = generateSalt();
            passSalt = concatPassSalt(pass, salt);
            key = hashPassSalt(passSalt, "SHA-256");
            aesKey = new SecretKeySpec(key, 0, key.length, "AES");
            ivRand = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivRand);
            encryptedText = padEncrypt();

            System.out.println("Salt: " + DatatypeConverter.printHexBinary(salt));
            System.out.println("IV: " + DatatypeConverter.printHexBinary(iv));
            System.out.println("Hashed key: " + DatatypeConverter.printHexBinary(key));
            System.out.println("AES encrypted Src File: " + DatatypeConverter.printHexBinary(encryptedText));
            //AES
            //TODO Check/compare output
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivRand);
            decryptedText = decrypt();
            //RSA
            //TODO Modular Exp, yay


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

    private byte [] hashPassSalt(byte [] key, String hashType)
    {
        try
        {
            MessageDigest digest = MessageDigest.getInstance(hashType);
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

    private byte [] padEncrypt()
    {
        try
        {
            int size = (int)sourceFile.length();
            byte [] encryptedText, paddedPlainText;
            byte [] plainText = new byte[size];

            FileInputStream inputStream = new FileInputStream(sourceFile);
            if(!encryptedZip.exists())
            {
                encryptedZip.createNewFile();
            }

            inputStream.read(plainText);
            paddedPlainText = padBlock(plainText, cipher.getBlockSize());

            encryptedText = cipher.doFinal(paddedPlainText);
            FileOutputStream outputStream = new FileOutputStream(encryptedZip);
            outputStream.write(encryptedText);

            outputStream.flush();
            outputStream.close();
            inputStream.close();
            return encryptedText;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return encryptedText;
    }

    private byte [] padBlock(byte [] plainText, int blockSize)
    {
        int padding = blockSize - (plainText.length % blockSize);
        byte [] paddedPlainText = new byte[plainText.length + padding];
        System.arraycopy(plainText, 0, paddedPlainText, 0, plainText.length);

        /*
            If the plaintext matches up to 128bit blocksize then just append
            an extra block of 10000000. If it does not, go to the end of the plaintext
            and append the appropriate amount of 0's after the initial 0x80 to make it a multiple
            of 16
         */
        paddedPlainText[plainText.length] = (byte)0x80;
        for(int i = 1; i < padding; i++)
        {
            paddedPlainText[plainText.length + i] = (byte)0;
        }
        return paddedPlainText;
    }

    private byte [] decrypt()
    {
        try
        {
            int size = (int)encryptedZip.length();
            FileInputStream inputStream = new FileInputStream(encryptedZip);
            FileOutputStream outputStream = new FileOutputStream(decryptedZip);
            byte [] encryptedText = new byte[size];
            byte [] paddedPlainText, decryptedText;

            inputStream.read(encryptedText);
            paddedPlainText = cipher.doFinal(encryptedText);
            decryptedText = removePadding(paddedPlainText);
            outputStream.write(decryptedText);

            inputStream.close();
            outputStream.flush();
            outputStream.close();

            return decryptedText;

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return decryptedText;
    }

    /*
       Return everything to left of the last 0x80 in array.
     */

    private byte [] removePadding(byte [] paddedText)
    {
        try
        {
            int padPosition = paddedText.length-1;
            while(padPosition > 0 && paddedText[padPosition] != (byte)0x80)
            {
                padPosition --;
            }

            byte [] plainText = new byte[padPosition];
            System.arraycopy(paddedText, 0, plainText, 0, padPosition);
            return plainText;
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            e.printStackTrace();
        }
        return paddedText;
    }
}