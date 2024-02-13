import org.bouncycastle.jce.provider.BouncyCastleProvider;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class crypto {
    private SecretKeySpec key = null;
    private byte[] data = null;
    private String mode = "";
    private Cipher cipher = null;
    static final int sizeKey = 32;
    static final int sizeIv = 8;
    static final int sizeIvCBC = 32;
    static final int sizeIvOFB = 32;
    private boolean initEncrypt = false;
    private boolean initDecrypt = false;


    static final String algorithm = "GOST3412-2015";
    private IvParameterSpec ivspec = null;

    crypto(){
        Security.addProvider(new BouncyCastleProvider());
        this.key = new SecretKeySpec(new byte[sizeKey], algorithm);
        this.data = new byte[0];
        ivspec = new IvParameterSpec(new byte[sizeKey]);
        try {
            this.cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS7Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    crypto(byte[] data, byte[] key, String mode, byte[] iv, String padding) { //NoPadding, PKCS7Padding
        Security.addProvider(new BouncyCastleProvider());
        this.mode = mode;
        byte[] keyByte = new byte[sizeKey];
        if (key.length > sizeKey){
            System.arraycopy(key, 0, keyByte, 0, sizeKey);
        } else {
            System.arraycopy(key, 0, keyByte, 0, key.length);
        }

        this.key = new SecretKeySpec(keyByte, algorithm);
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, data.length);
        if (iv == null) {
            iv = new byte[sizeIv];
            SecureRandom rnd = new SecureRandom();
            rnd.nextBytes(iv);
        } else {
            /*
            byte[] ivByte = new byte[sizeIv];
            if (iv.length > sizeIv){
                System.arraycopy(key, 0, ivByte, 0, sizeIv);
            } else {
                System.arraycopy(key, 0, ivByte, 0, iv.length);
            }
            iv = ivByte;

             */
        }

        try {
            ivspec = new IvParameterSpec(iv);
            this.cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
            /*
            switch (mode){
                case "ECB":
                    this.cipher = Cipher.getInstance("GOST3412-2015/ECB/PKCS7Padding");
                    break;
                case "CFB":
                    this.cipher = Cipher.getInstance("GOST3412-2015/CFB/PKCS7Padding");
                    ivspec = new IvParameterSpec(iv);
                    break;
                case "OFB":
                    this.cipher = Cipher.getInstance("GOST3412-2015/OFB/PKCS7Padding");
                    ivspec = new IvParameterSpec(iv);
                    break;
                case "CTR":
                    this.cipher = Cipher.getInstance("GOST3412-2015/CTR/PKCS7Padding");
                    ivspec = new IvParameterSpec(iv);
                    break;
                case "CBC":
                default:
                    this.cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS7Padding");
                    ivspec = new IvParameterSpec(iv);
                    break;
            }
             */
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    void setData(byte[] data) {
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, this.data.length);
    }

    byte[] getIV(){
        return ivspec.getIV();
    }

    byte[] encryptGost(){
        initCipherEncrypt();
        byte[] cipherText = null;
        try {

            cipherText = cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }


        return cipherText;
    }

    void initCipherEncrypt(){
        if (initEncrypt){
            return;
        }
        try {
            if (mode.equals("ECB")){
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
            }

        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        initEncrypt = true;
        initDecrypt = false;
    }

    void initCipherDecrypt(){
        if (initDecrypt){
            return;
        }
        if (!mode.equals("ECB")){
            int ivSize = sizeIv;
            if (mode.equals("CBC")){
                ivSize = sizeIvCBC;
            } else if (mode.equals("OFB") || mode.equals("CFB")) {
                ivSize = sizeIvOFB;
            }
            byte[] iv = new byte[ivSize];
            System.arraycopy(data, 0, iv, 0, ivSize);
            ivspec = new IvParameterSpec(iv);

            byte[] dataNew = new byte[data.length - ivSize];
            System.arraycopy(data, ivSize, dataNew, 0, dataNew.length);
            data = dataNew;
        }
        try {
            if (mode.equals("ECB")){
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
            }

        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        initEncrypt = false;
        initDecrypt = true;
    }

    byte[] encryptUpdateGost(){
        initCipherEncrypt();
        return cipher.update(data);
    }

    byte[] decryptUpdateGost(){
        initCipherDecrypt();
        return cipher.update(data);
    }

    byte[] decryptGost(){
        initCipherDecrypt();
        byte[] out = null;
        try {
            out = cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return out;
    }

    public static void main(String[] args) {
        byte[] key = new byte[10];
        byte[] data = "Hello".getBytes();

        crypto Cr = new crypto(data, key, "CTR", null, "PKCS7Padding");
        byte[] ct = Cr.encryptGost();
        Cr.data = ct;
        byte[] dt = Cr.decryptGost();
        System.out.println(new String(dt));

    }


}
