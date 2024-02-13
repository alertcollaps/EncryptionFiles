package File;

import Crypto.Encryption.Crypto;
import Crypto.Encryption.Mode;

public class Encrypt {
    static Mode mode = Mode.OFB;
    public static void EncryptFile(String pathSrc, String pathDest, String key){
        byte[] data = Open.read(pathSrc);
        Crypto cr = new Crypto(key, mode);

        cr.encrypt(data);
        byte[] encData = cr.getLastOutWithIV();
        Open.write(pathDest, encData);
    }

    public static void DecryptFile(String pathSrc, String pathDest, String key){
        byte[] data = Open.read(pathSrc);
        Crypto cr = new Crypto(key, mode);


        byte[] decData = cr.decryptWithIvData(data);
        Open.write(pathDest, decData);
    }

    public static void main(String[] args) {
        EncryptFile("t.txt", "tt.txt", "123");
        DecryptFile("tt.txt", "newFile.txt", "123");
    }
}
