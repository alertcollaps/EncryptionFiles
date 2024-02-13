import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class EncryptionTest {

    public static void main(String[] args) {
        EncryptionTest enc = new EncryptionTest();
        try {
            String GOST = "GOST3412-2015";
            String AES = "AES";
            System.out.println(GOST + "-CBC");
            enc.encrypt(GOST);
            System.out.println(AES + "-CBC");
            enc.encrypt(AES);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
    void encrypt(String algo) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Security.addProvider(new BouncyCastleProvider());

        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        SecretKeySpec key = new SecretKeySpec("C0BAE23DF8B51807B3E17D21925FADF2".getBytes(), algo);

        Cipher cipherEnc = Cipher.getInstance(algo + "/CBC/NoPadding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, key, iv);
        Cipher cipherEnc1 = Cipher.getInstance(algo + "/CBC/NoPadding");
        cipherEnc1.init(Cipher.ENCRYPT_MODE, key, iv);
        Cipher cipherDec = Cipher.getInstance(algo + "/CBC/NoPadding");
        cipherDec.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] ct1 = cipherEnc.doFinal(dataByte);
        byte[] ct2 = cipherEnc1.update(dataByte1);
        byte[] ct3 = cipherEnc1.update(dataByte2);
        byte[] ct4 = cipherEnc1.doFinal();

        System.out.println(testCrypto.bytesToHex(ct1));
        System.out.println(testCrypto.bytesToHex(ct2) + testCrypto.bytesToHex(ct3));
        System.out.println(testCrypto.bytesToHex(ct4));

    }




    public static final byte[] dataByte = {
            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
            (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88,

            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
            (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a,

            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
            (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a, (byte)0x00,

            (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99,
            (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a, (byte)0x00, (byte)0x11,

    };

    public static final byte[] dataByte1 = {
            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x00,
            (byte)0xff, (byte)0xee, (byte)0xdd, (byte)0xcc, (byte)0xbb, (byte)0xaa, (byte)0x99, (byte)0x88,

            (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
            (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a,
    };

    public static final byte[] dataByte2 = {
            (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
            (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a, (byte)0x00,

            (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99,
            (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xee, (byte)0xff, (byte)0x0a, (byte)0x00, (byte)0x11,
    };

}
