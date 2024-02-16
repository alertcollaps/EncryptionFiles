package Crypto.Encryption;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class Crypto {
    static final String algorithm = "GOST3412-2015";
    static final String algorithmHash = "GOST3411";
    static String padding = "PKCS7Padding";
    static String noPadding = "NoPadding";
    static int keySize = 32; //В байтах
    static int macSize = 8; //В байтах

    private Cipher cipherEnc = null;
    private Cipher cipherMac = null;
    private Cipher cipherDec = null;
    private SecretKeySpec key = null;
    private IvParameterSpec iv;
    private byte[] out = null;
    public Mode mode;

    public Crypto(Mode mode){
        Security.addProvider(new BouncyCastleProvider());
        key = new SecretKeySpec(new byte[keySize], algorithm);
        this.mode = mode;
        try {
            cipherMac = Cipher.getInstance(algorithm + "/" + mode + "/" + noPadding);
            cipherEnc = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
            cipherDec = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        try {
            cipherMac.init(Cipher.ENCRYPT_MODE, this.key);
            cipherEnc.init(Cipher.ENCRYPT_MODE, this.key);
            cipherDec.init(Cipher.DECRYPT_MODE, this.key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public Crypto(byte[] key, Mode mode){
        Security.addProvider(new BouncyCastleProvider());
        initKey(key);
        initIV(new byte[0], mode.ivSize);
        this.mode = mode;
        try {
            cipherMac = Cipher.getInstance(algorithm + "/" + mode + "/" + noPadding);
            cipherEnc = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
            cipherDec = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        try {
            cipherMac.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
            cipherEnc.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
            cipherDec.init(Cipher.DECRYPT_MODE, this.key, this.iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public Crypto(String key, Mode mode){
        this(Hash(key.getBytes()), mode);
    }

    public Crypto(byte[] key, Mode mode, byte[] iv){
        Security.addProvider(new BouncyCastleProvider());
        initKey(key);
        initIV(iv, mode.ivSize);
        this.mode = mode;
        try {
            cipherMac = Cipher.getInstance(algorithm + "/" + mode + "/" + noPadding);
            cipherEnc = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
            cipherDec = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }


        try {
            cipherMac.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
            cipherEnc.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
            cipherDec.init(Cipher.DECRYPT_MODE, this.key, this.iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public Crypto(String key, Mode mode, byte[] iv){
        this(Hash(key.getBytes()), mode, iv);
    }

    public byte[] getLastOutWithIV(){
        byte[] iv = this.iv.getIV();
        byte[] ivOut = new byte[iv.length + out.length];
        System.arraycopy(iv, 0, ivOut, 0, iv.length);
        System.arraycopy(out, 0, ivOut, iv.length, out.length);
        return ivOut;
    }

    public byte[] encrypt(byte[] data){
        try {
            out = cipherEnc.doFinal(data);
            return out;
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] data){
        try {
            out = cipherDec.doFinal(data);
            return out;
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(byte[] data, byte[] key){
        initKey(key);
        try {
            cipherEnc.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        try {
            out = cipherEnc.doFinal(data);
            return out;
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] data, byte[] key){
        initKey(key);
        try {
            cipherDec.init(Cipher.DECRYPT_MODE, this.key, this.iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        try {
            out = cipherDec.doFinal(data);
            return out;
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decryptWithIvData(byte[] dataByte){
        byte[] iv = new byte[mode.ivSize];
        byte[] data = new byte[dataByte.length - mode.ivSize];

        System.arraycopy(dataByte, 0, iv, 0, mode.ivSize);
        System.arraycopy(dataByte, mode.ivSize, data, 0, data.length);

        initIV(iv, mode.ivSize);
        try {
            cipherDec.init(Cipher.DECRYPT_MODE, this.key, this.iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        return decrypt(data);
    }

    void initKey(byte[] key){
        { //Выравнивание ключа
            byte[] keyByte = new byte[keySize];
            System.arraycopy(key, 0, keyByte, 0, Math.min(key.length, keySize));
            this.key = new SecretKeySpec(keyByte, algorithm);
        }
    }

    void initIV(byte[] iv, int ivSize){
        if (ivSize == 0){
            this.iv = null;
            return;
        }
        byte[] ivByte = new byte[ivSize];
        if (iv.length < ivSize){
            SecureRandom rnd = new SecureRandom();
            rnd.nextBytes(ivByte);
        }

        System.arraycopy(iv, 0, ivByte, 0, Math.min(iv.length, ivSize));
        this.iv = new IvParameterSpec(ivByte);
    }

    static public byte[] Hash(byte[] data) { //Hash GOST3411
        Security.addProvider(new BouncyCastleProvider());
        try {
            MessageDigest md = MessageDigest.getInstance(algorithmHash);
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] imitovstavka(byte[] data){
        byte[] dataByte = new byte[data.length];
        System.arraycopy(data, 0, dataByte, 0, dataByte.length);
        byte[] out = new byte[macSize];

        CMac mm = new CMac(new GOST3412_2015Engine(), macSize*8);

        CipherParameters cipherParameters = new KeyParameter(key.getEncoded());
        mm.init(cipherParameters);
        mm.update(dataByte, 0, dataByte.length);
        mm.doFinal(out, 0);

        return out;
    }

    public static void main(String[] args) {

    }

}
