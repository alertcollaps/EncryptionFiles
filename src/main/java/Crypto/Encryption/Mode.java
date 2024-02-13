package Crypto.Encryption;

public class Mode {
    public int ivSize;
    public String name;

    private Mode(String name, int ivSize){
        this.name = name;

        this.ivSize = ivSize;
    }

    @Override
    public boolean equals(Object obj) {
        Mode obj1 = (Mode) obj;

        return obj1.name.equals(this.name);
    }

    @Override
    public String toString() {
        return this.name;
    }

    public static Mode ECB = new Mode("ECB", 0);
    public static Mode CBC = new Mode("CBC", 32);
    public static Mode OFB = new Mode("OFB", 32);
    public static Mode CFB = new Mode("CFB", 32);
    public static Mode CTR = new Mode("CTR", 8);
}
