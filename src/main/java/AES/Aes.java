package AES;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.rmi.UnexpectedException;
import java.util.Arrays;

import static AES.Funktionen.*;
import static AES.GaloisField.*;

public class Aes {
    private char[] text;
    private final KeyGen keyGen;
    private final boolean entschluesseln;
    private final int roundMax;
    private int round = 0;

    public Aes(char[] text, char[] key, boolean entschluesseln) {
        this.text = text.clone();
        roundMax = switch (key.length) {
            case 16 -> 10;
            case 24 -> 12;
            case 32 -> 14;
            default -> throw new IllegalArgumentException("Der Schlüssel hat die falsche Länge");
        };
        keyGen = new KeyGen(key, entschluesseln);
        this.entschluesseln = entschluesseln;
    }

    static char[] aesBlock(char[] text, char[] key, boolean entschluesseln) {
        Aes aes = new Aes(text, key, entschluesseln);
        for (int i = 0; i <= aes.roundMax; i++) aes.aesRound();
        return aes.getText();
    }

    static void aesFileCBC(String input, String output, char[] key, boolean entschluesseln) {
        aesFileCBCIV(input, output, new char[16], key, entschluesseln);
    }

    static void aesFileCBCIV(String input, String output, char[] iv, char[] key, boolean entschluesseln) {
        try (FileInputStream read = new FileInputStream(input); FileOutputStream write = new FileOutputStream(output)) {
            byte[] b = new byte[16];
            int anz;
            char[] merke = iv.clone();
            if (entschluesseln) {
                while ((anz = read.read(b)) == 16) {
                    char[] in = byteArr2arr(b);
                    char[] crypt = aesBlock(in, key, true);
                    xor(merke, crypt);
                    for (int i = 15; i >= 0; i--) {
                        if (merke[i] != 0 && i > 13) break;
                        if (merke[i] != 0) {
                            merke = Arrays.copyOfRange(merke, 0, i + 1);
                            break;
                        }
                    }
                    write.write(arr2byteArr(merke));
                    merke = in;
                }
            } else {
                while ((anz = read.read(b)) == 16) {
                    char[] in = byteArr2arr(b);
                    xor(in, merke);
                    merke = aesBlock(in, key, false);
                    write.write(arr2byteArr(merke));
                }
                if (anz != -1) {
                    for (int i = anz; i < 16; i++) b[i] = 0;
                    char[] in = byteArr2arr(b);
                    xor(in, merke);
                    merke = aesBlock(in, key, false);
                    write.write(arr2byteArr(merke));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public void aesRound() {
        if (round > roundMax) throw new TooManyRoundsException("Maximale Rundenanzahl: " + roundMax + " überschritten");
        if (entschluesseln) aesRoundEntsch(text, keyGen.getNextKey(), round, roundMax);
        else aesRoundVersch(text, keyGen.getNextKey(), round, roundMax);
        round++;
    }

    static void aesRoundVersch(char[] input, char[] key, int round, int roundMax) {
        if (round == 0) addRoundKey(input, key);
        else {
            substituteByte(input);
            shiftRow(input);
            if (round != roundMax) mixColumn(input);
            addRoundKey(input, key);
        }
    }

    static void aesRoundEntsch(char[] input, char[] key, int round, int roundMax) {
        if (round == roundMax) addRoundKey(input, key);
        else {
            addRoundKey(input, key);
            if (round != 0) mixColumnInverse(input);
            shiftRowInverse(input);
            substituteByteInverse(input);
        }
    }

    public void substituteByte() {
        substituteByte(text);
    }

    static void substituteByte(char[] input) {
        subByteIntern(input, sBox);
    }

    public void substituteByteInverse() {
        substituteByteInverse(text);
    }

    static void substituteByteInverse(char[] input) {
        subByteIntern(input, sBoxInverse);
    }

    private static void subByteIntern(char[] input, char[][] sBox) {
        for (int i = 0; i < 16; i++) {
            int zeile = (input[i] >> 4);
            int spalte = (input[i] & 0xF);
            input[i] = sBox[zeile][spalte];
        }
    }

    public void shiftRow() {
        shiftRow(text);
    }

    static void shiftRow(char[] input) {
        // Reihe 2
        char tmp = input[1];
        input[1] = input[5];
        input[5] = input[9];
        input[9] = input[13];
        input[13] = tmp;
        // Reihe 3
        tmp = input[2];
        input[2] = input[10];
        input[10] = tmp;
        tmp = input[6];
        input[6] = input[14];
        input[14] = tmp;
        // Reihe 4
        tmp = input[3];
        input[3] = input[15];
        input[15] = input[11];
        input[11] = input[7];
        input[7] = tmp;
    }

    public void shiftRowInverse() {
        shiftRowInverse(text);
    }

    static void shiftRowInverse(char[] input) {
        // Reihe 2
        char tmp = input[1];
        input[1] = input[13];
        input[13] = input[9];
        input[9] = input[5];
        input[5] = tmp;
        // Reihe 3
        tmp = input[2];
        input[2] = input[10];
        input[10] = tmp;
        tmp = input[6];
        input[6] = input[14];
        input[14] = tmp;
        //Reihe 4
        tmp = input[3];
        input[3] = input[7];
        input[7] = input[11];
        input[11] = input[15];
        input[15] = tmp;
    }

    public void mixColumn() {
        mixColumn(text);
    }

    static void mixColumn(char[] input) {
        char[] tmp = new char[4];
        for (int spalte = 0; spalte < 4; spalte++) {
            System.arraycopy(input, spalte * 4, tmp, 0, 4);
            tmp = matrixMul(tmp);
            System.arraycopy(tmp, 0, input, spalte * 4, 4);
        }
    }

    public void mixColumnInverse() {
        mixColumnInverse(text);
    }

    static void mixColumnInverse(char[] input) {
        char[] tmp = new char[4];
        for (int spalte = 0; spalte < 4; spalte++) {
            System.arraycopy(input, spalte * 4, tmp, 0, 4);
            tmp = matrixMulInvers(tmp);
            System.arraycopy(tmp, 0, input, spalte * 4, 4);
        }
    }

    public void addRoundKey() {
        addRoundKey(text, keyGen.getNextKey());
    }

    static void xor(char[] inplace, char[] input) {
        addRoundKey(inplace, input);
    }

    static void addRoundKey(char[] input, char[] key) {
        for (int i = 0; i < input.length; i++) {
            input[i] ^= key[i];
        }
    }

    char[] getText() {
        return text;
    }

    char[] getKey() {
        return keyGen.getKey();
    }
}
