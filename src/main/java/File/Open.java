package File;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Scanner;

public class Open {
    static public byte[] read(String path){
        File file = new File(path);
        if (!file.exists()){
            System.out.println("Файл не найден");
            return null;
        }
        byte[] out = new byte[(int) file.length()];

        try (FileInputStream fis = new FileInputStream(file)){
            fis.read(out);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return out;
    }

    static public void write(String path, byte[] data){
        File file = new File(path);
        if (!file.exists()){
            try {
                boolean b = file.createNewFile();
                if (!b){
                    System.out.println("Error create file");
                    return;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        try (FileOutputStream fos = new FileOutputStream(file)){
            fos.write(data);


        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public static void main(String[] args) {

    }
}
