import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
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
    private byte [] encryptedText;
    private byte [] decryptedText;
    private final String geoffPubMod = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190" +
            "ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d" +
            "3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c8652" +
            "01fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
    private BigInteger e = new BigInteger("65537");

    private final File SOURCEFILE = new File ("src.zip");
    private final File ENCRYPTEDZIP = new File("encrypted.zip");
    private final File DECRYPTEDZIP = new File("decrypted.zip");

    public SymmEncrypt(String pass, String encryptionType)
    {
        try
        {
            cipher = Cipher.getInstance(encryptionType);
            byte[] salt = generateSalt();
            byte[] iv = generateSalt();
            byte[] passSalt = concatPassSalt(pass, salt);
            byte[] key = hashPassSalt(passSalt);
            SecretKey aesKey = new SecretKeySpec(key, 0, key.length, "AES");
            IvParameterSpec ivRand = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivRand);
            encryptedText = padAndEncrypt();

            System.out.println("Salt: " + DatatypeConverter.printHexBinary(salt));
            System.out.println("IV: " + DatatypeConverter.printHexBinary(iv));
            System.out.println("SHA-256 Hashed key: " + DatatypeConverter.printHexBinary(key));
            System.out.println("AES encrypted Src File: " + DatatypeConverter.printHexBinary(encryptedText));

            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivRand);
            decryptedText = decrypt();

            //RSA
            String rsaPassword = modExp(pass, e, geoffPubMod).toString(16);
            System.out.println("RSA Encrypted Password: " + rsaPassword);


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

    private byte [] hashPassSalt(byte[] key)
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

    private byte [] padAndEncrypt()
    {
        try
        {
            int size = (int) SOURCEFILE.length();
            byte [] paddedPlainText;
            byte [] plainText = new byte[size];

            FileInputStream inputStream = new FileInputStream(SOURCEFILE);
            if(!ENCRYPTEDZIP.exists())
            {
                ENCRYPTEDZIP.createNewFile();
            }

            inputStream.read(plainText);
            paddedPlainText = padBlock(plainText, cipher.getBlockSize());

            encryptedText = cipher.doFinal(paddedPlainText);
            FileOutputStream outputStream = new FileOutputStream(ENCRYPTEDZIP);
            outputStream.write(encryptedText);

            outputStream.flush();
            outputStream.close();
            inputStream.close();
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
            an extra block of 10000000D. If it does not, go to the end of the plaintext
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
            int size = (int) ENCRYPTEDZIP.length();
            FileInputStream inputStream = new FileInputStream(ENCRYPTEDZIP);
            FileOutputStream outputStream = new FileOutputStream(DECRYPTEDZIP);
            byte [] encryptedText = new byte[size];
            byte [] paddedPlainText;

            inputStream.read(encryptedText);
            paddedPlainText = cipher.doFinal(encryptedText);
            decryptedText = removePadding(paddedPlainText);
            outputStream.write(decryptedText);

            inputStream.close();
            outputStream.flush();
            outputStream.close();

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return decryptedText;
    }

    private byte [] removePadding(byte [] paddedText)
    {
        try
        {
            int padPosition = paddedText.length-1;
            while(padPosition > 0 && paddedText[padPosition] != (byte)0x80)
            {
                padPosition --;
            }
            /*
               Return everything to left of the last 0x80 in array.
            */
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

    private static BigInteger modExp(String pass, BigInteger e, String nmod)
    {
        /*
           result := 1
           while exponent > 0
              if (exponent mod 2 == 1):
                 result := (result * base) mod modulus
              exponent := exponent >> 1
              base = (base * base) mod modulus
           return result

           Check if least most significant bit is set
           if so calculate y*p(mod n)
           logical shift right
           calculate p^2(mod n)
           Continue while exponent greater than zero
         */
        BigInteger p = new BigInteger(pass.getBytes(StandardCharsets.UTF_8));
        BigInteger n = new BigInteger(nmod, 16);
        BigInteger y = new BigInteger("1");

        while(e.compareTo(BigInteger.ZERO) > 0)
        {
            if(e.testBit(0))
            {
                y = (y.multiply(p)).mod(n);
            }
            e = e.shiftRight(1);
            p = (p.multiply(p)).mod(n);

        }

        return y.mod(n);
    }
}