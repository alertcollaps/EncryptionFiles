import File.Encrypt;

public class main {
    public static void main(String[] args) {
        Encrypt.EncryptFile("t.txt", "tt.txt", "123");
        Encrypt.DecryptFile("tt.txt", "newFile.txt", "123");
    }
}
