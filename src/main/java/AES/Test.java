package AES;

import javax.management.openmbean.ArrayType;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.SQLOutput;
import java.util.Arrays;

import static AES.Funktionen.*;
import static AES.GaloisField.*;
import static AES.Aes.*;

public class Test {
    public static void main(String[] args) {

        test();
        // uebung();
    }

    public static void uebung() {
        // 8
        System.out.println("8: " + char2hexString(gfMul(binString2char("11001011"), binString2char("00110101"))));
        // 9
        System.out.println("9: " + arr2hexString(matrixMul(new char[]{2, 3, 5, 1})));
        // 10 a
        char[] input = hexString2arr("05 13 36 28 87 5a 30 8d 31 a2 98 a2 e0 37 07 35");
        substituteByte(input);
        System.out.println("10a: " + arr2hexString(input, true));
        // b
        shiftRow(input);
        System.out.println("10b: " + arr2hexString(input, true));
        //c
        mixColumn(input);
        System.out.println("10c: " + arr2hexString(input, true));
        System.out.println("10c: " + arr2hexString(matrixMul(hexString2arr("6b be 46 18")), true));
    }

    public static void test() {
        // Ver-/Entschlüsseln
        if (true) {
            char[] m = hexString2arr("53 74 61 72 74 62 65 69 73 70 69 65 6C 20 7A 75");
            System.out.println("start  : " + arr2hexString(m, true) + " : " + arr2hexString(m, true)
                    + " : " + arr2hexString(m, true));
            char[] key1 = hexString2arr("00112233445566778899aabbccddeeff");
            char[] key2 = hexString2arr("00112233445566778899aabbccddeeff 0011223344556677");
            char[] key3 = hexString2arr("00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff");

            char[] versch1 = aesBlock(m, key1, false); // Ziel: 58 59 12 30 05 33 20 76 FF 89 13 90 96 90 93 2A
            char[] versch2 = aesBlock(m, key2, false);
            char[] versch3 = aesBlock(m, key3, false);
            System.out.println("encrypt: " + arr2hexString(versch1, true) + " : " + arr2hexString(versch2, true)
                    + " : " + arr2hexString(versch3, true));
            char[] entsch1 = aesBlock(versch1, key1, true);
            char[] entsch2 = aesBlock(versch2, key2, true);
            char[] entsch3 = aesBlock(versch3, key3, true);
            System.out.println("decrypt: " + arr2hexString(entsch1, true) + " : " + arr2hexString(entsch2, true)
                    + " : " + arr2hexString(entsch3, true));
        }

        // Funktionen + Inverse
        if (false) {
            char[] input = hexString2arr("6B BE 46 18 17 3A C5 34 C7 9A 05 5D E1 7D 04 3A");
            // Mix Colum
            System.out.println(arr2hexString(input, true));
            mixColumn(input);
            System.out.println(arr2hexString(input, true));
            mixColumnInverse(input);
            System.out.println(arr2hexString(input, true));
            // shift row
            System.out.println("\n" + arr2hexString(input, true));
            shiftRow(input);
            System.out.println(arr2hexString(input, true));
            shiftRowInverse(input);
            System.out.println(arr2hexString(input, true));
            // sub Byte
            System.out.println("\n" + arr2hexString(input, true));
            substituteByte(input);
            System.out.println(arr2hexString(input, true));
            substituteByteInverse(input);
            System.out.println(arr2hexString(input, true));
        }

        if (false) {
            char[] m = hexString2arr("53 74 61 72 74 62 65 69 73 70 69 65 6C 20 7A 75");
            char[] c = hexString2arr("58 59 12 30 05 33 20 76 FF 89 13 90 96 90 93 2A");
            char[] key = hexString2arr("00112233445566778899aabbccddeeff");
            Aes ver = new Aes(m, key, false);
            Aes ent = new Aes(c, key, true);
            for (int i = 0; i < 11; i++) {
                System.out.println(i + ": " + arr2hexString(ver.getText(), true) + " : " + arr2hexString(ver.getKey(), true)
                        + " : " + arr2hexString(ent.getText(), true) + " : " + arr2hexString(ent.getKey(), true));
                ver.aesRound();
                ent.aesRound();
            }
            System.out.println("11: " + arr2hexString(ver.getText(), true)
                    + " :                                                  : " + arr2hexString(ent.getText(), true));
        }

        // byte[] <-> char[]
        if (false) {
            try (FileInputStream read = new FileInputStream("C:/Users/f-luc/Downloads/test.txt")) {
                byte[] b = new byte[16];
                read.read(b);
                System.out.println(Arrays.toString(b));
                System.out.println(arr2hexString(byteArr2arr(b)));
                System.out.println(Arrays.toString(arr2byteArr(byteArr2arr(b))));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        // Datei Ver-/Entschlüsseln
        if (true) {
            String input = "C:/Users/f-luc/Downloads/test.txt";
            String output = "C:/Users/f-luc/Downloads/testo.txt";
            String output2 = "C:/Users/f-luc/Downloads/testoo.txt";
            char[] key = hexString2arr("00112233445566778899aabbccddeeff");
            aesFileCBC(input, output, key, false);
            aesFileCBC(output, output2, key, true);
        }

        // Zeitmessung
        if (true) {
            String input = "C:/Users/f-luc/Downloads/start.txt";
            String output = "C:/Users/f-luc/Downloads/mitte.txt";
            String output2 = "C:/Users/f-luc/Downloads/ende.txt";
            char[] key = hexString2arr("00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff");

            long start = System.currentTimeMillis();
            aesFileCBC(input, output, key, false);
            long mitte = System.currentTimeMillis();
            aesFileCBC(output, output2, key, true);
            long ende = System.currentTimeMillis();
            System.out.println("Verschlüsseln: " + (mitte - start));
            System.out.println("Entschlüsseln: " + (ende - mitte));
        }
    }
}
