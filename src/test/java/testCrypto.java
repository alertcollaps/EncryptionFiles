import Crypto.Encryption.Crypto;
import Crypto.Encryption.Mode;
import File.Encrypt;

public class testCrypto {
    //"8899aabb ccddeeff 00112233 44556677 fedcba98 76543210 01234567 89abcdef";
    public static final byte[] keyByte = {
                                            (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                                            (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
                                            (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33,
                                            (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77,

                                            (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                                            (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10,
                                            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
                                            (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
                                         };

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

    public static final byte[] ivByte = {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0,
    };

    public static final byte[] ivByteCBC = {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0,
            (byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4,
            (byte)0xe5, (byte)0xf0, (byte)0x01, (byte)0x12,
            (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56,
            (byte)0x67, (byte)0x78, (byte)0x89, (byte)0x90,
            (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15,
            (byte)0x16, (byte)0x17, (byte)0x18, (byte)0x19,
    };

    public static final byte[] ivByteOFB = {
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
            (byte)0x90, (byte)0xab, (byte)0xce, (byte)0xf0,
            (byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4,
            (byte)0xe5, (byte)0xf0, (byte)0x01, (byte)0x12,
            (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56,
            (byte)0x67, (byte)0x78, (byte)0x89, (byte)0x90,
            (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15,
            (byte)0x16, (byte)0x17, (byte)0x18, (byte)0x19,
    };

    public static final byte[] ivByteCFB = ivByteOFB;

    public static void testECB() {
        String mode = "ECB";
        test(Mode.ECB, ivByte);
    }

    public static void testCBC() {
        String mode = "CBC";
        test(Mode.CBC, ivByteCBC);
    }

    public static void testCTR() {
        String mode = "CTR";
        test(Mode.CTR, ivByte);
    }

    public static void testOFB() {
        String mode = "OFB";
        test(Mode.OFB, ivByteOFB);
    }

    public static void testCFB() {
        String mode = "CFB";
        test(Mode.CFB, ivByteCFB);
    }

    public static void testImitovstavka() {
        String mode = "Imitovstavka";
        Crypto cr = new Crypto(keyByte, Mode.CBC, new byte[32]);
        byte[] imit = cr.imitovstavka(dataByte);

        System.out.println("------" + mode + "------");
        System.out.println("Imitivstavka text: " + bytesToHex(imit));
    }

    public static void testCBCUpdate(){
        String mode = "CBC";
        crypto cr = new crypto(dataByte1, keyByte, mode, ivByteCBC, "NoPadding");
        byte[] cipherText1 = cr.encryptUpdateGost();
        cr.setData(dataByte2);
        byte[] cipherText2 = cr.encryptUpdateGost();


        byte[] cipherTextAndIv1 = new byte[cipherText1.length + ivByteCBC.length];
        System.arraycopy(ivByteCBC, 0, cipherTextAndIv1, 0, ivByteCBC.length);
        System.arraycopy(cipherText1, 0, cipherTextAndIv1, ivByteCBC.length, cipherText1.length);
        cr.setData(cipherTextAndIv1);

        cr.setData(cipherTextAndIv1);
        byte[] decryptedText1 = cr.decryptUpdateGost();
        cr.setData(cipherText2);
        byte[] decryptedText2 = cr.decryptUpdateGost();


        System.out.println("------" + mode + " update" + "------");
        System.out.println("Encrypted text: " + bytesToHex(cipherText1) + bytesToHex(cipherText2));
        System.out.println("Decrypted text: " + bytesToHex(decryptedText1) + bytesToHex(decryptedText2));
    }


    public static void test(Mode mode, byte[] iv){
        Crypto cr = new Crypto(keyByte, mode, iv);
        byte[] cipherText = cr.encrypt(dataByte);
        byte[] cipherTextAndIv = null;
        if (!mode.name.equals("ECB")){
            cipherTextAndIv = new byte[cipherText.length + iv.length];
            System.arraycopy(iv, 0, cipherTextAndIv, 0, iv.length);
            System.arraycopy(cipherText, 0, cipherTextAndIv, iv.length, cipherText.length);
        } else {
            cipherTextAndIv = cipherText;
        }


        byte[] decryptedText = cr.decrypt(cipherText);
        System.out.println("------" + mode + "------");
        System.out.println("Encrypted text: " + bytesToHex(cipherText));
        System.out.println("Decrypted text: " + bytesToHex(decryptedText));
    }

    public static void main(String[] args) {
        testECB();
        testCBC();
        testCBCUpdate();
        testCTR(); //Гаммирование
        testOFB();
        testCFB();
        testImitovstavka();
    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
