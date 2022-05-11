package AES;

import static AES.Funktionen.*;

public class KeyGen {
    private char[][] keys;
    private final boolean entschluesseln;
    private int round = 0;
    private final int maxRounds;

    public KeyGen(char[] keyIn, boolean entschluesseln) {
        char[] key = keyIn.clone();
        this.maxRounds = switch (key.length) {
            case 16 -> 10;
            case 24 -> 12;
            case 32 -> 14;
            default -> throw new IllegalArgumentException("Der Schlüssel hat die falsche Länge");
        };
        this.entschluesseln = entschluesseln;
        keys = new char[key.length + 28][4];
        for (int i = 0; i < key.length / 4; i++) {
            System.arraycopy(key, i * 4, keys[i], 0, 4);
        }
        genKeys();
    }

    private void genKeys() {
        if (maxRounds == 10) genKeys128();
        else if (maxRounds == 12) genKeys196();
        else genKeys256();
        for (int i = 0; i < keys.length; i++) {
            //System.out.println(i + ": " + arr2hexString(keys[i]));
        }
    }

    private void genKeys128() {
        for (int i = 0; i < 10; i++) {
            int index = i * 4;
            keys[index + 4] = xor(keys[index], g(keys[index + 3], getRC(i)));
            keys[index + 5] = xor(keys[index + 1], keys[index + 4]);
            keys[index + 6] = xor(keys[index + 2], keys[index + 5]);
            keys[index + 7] = xor(keys[index + 3], keys[index + 6]);
        }
    }

    private void genKeys196() {
        for (int i = 0; i < 8; i++) {
            int index = i * 6;
            keys[index + 6] = xor(keys[index], g(keys[index + 3], getRC(i)));
            keys[index + 7] = xor(keys[index + 1], keys[index + 6]);
            keys[index + 8] = xor(keys[index + 2], keys[index + 7]);
            keys[index + 9] = xor(keys[index + 3], keys[index + 8]);
            if (i != 7) {
                keys[index + 10] = xor(keys[index + 4], keys[index + 9]);
                keys[index + 11] = xor(keys[index + 5], keys[index + 10]);
            }
        }
    }

    private void genKeys256() {
        for (int i = 0; i < 7; i++) {
            int index = i * 8;
            keys[index + 8] = xor(keys[index], g(keys[index + 3], getRC(i)));
            keys[index + 9] = xor(keys[index + 1], keys[index + 8]);
            keys[index + 10] = xor(keys[index + 2], keys[index + 9]);
            keys[index + 11] = xor(keys[index + 3], keys[index + 10]);
            if (i != 6) {
                keys[index + 12] = xor(keys[index + 4], h(keys[index + 11]));
                keys[index + 13] = xor(keys[index + 5], keys[index + 12]);
                keys[index + 14] = xor(keys[index + 6], keys[index + 13]);
                keys[index + 15] = xor(keys[index + 7], keys[index + 14]);
            }
        }
    }

    char[] getNextKey() {
        char[] ergebnis = getKey();
        round++;
        return ergebnis;
    }

    char[] getKey() {
        char[] ergebnis = new char[16];
        int index = entschluesseln ? maxRounds - round : round;
        System.arraycopy(keys[index * 4], 0, ergebnis, 0, 4);
        System.arraycopy(keys[index * 4 + 1], 0, ergebnis, 4, 4);
        System.arraycopy(keys[index * 4 + 2], 0, ergebnis, 8, 4);
        System.arraycopy(keys[index * 4 + 3], 0, ergebnis, 12, 4);
        return ergebnis;
    }

    private static char getRC(int i) {
        if (i < 8) return (char) (1 << i);
        return switch (i) {
            case 8 ->  0b00011011;
            case 9 ->  0b00110110;
            default -> throw new IllegalArgumentException("Test"); //0b01101100;
        };
    }

    private static char[] xor(char[] inplace, char[] input) {
        char[] ergebnis = new char[4];
        ergebnis[0] = (char) (inplace[0] ^ input[0]);
        ergebnis[1] = (char) (inplace[1] ^ input[1]);
        ergebnis[2] = (char) (inplace[2] ^ input[2]);
        ergebnis[3] = (char) (inplace[3] ^ input[3]);
        return ergebnis;
    }

    static char[] g(char[] input, char rc) {
        char[] ergebnis = new char[4];
        ergebnis[1] = input[2];
        ergebnis[2] = input[3];
        ergebnis[0] = input[1];
        ergebnis[3] = input[0];
        for (int i = 0; i < 4; i++) {
            int zeile = (ergebnis[i] >> 4);
            int spalte = (ergebnis[i] & 0xF);
            ergebnis[i] = sBox[zeile][spalte];
        }
        ergebnis[0] ^= rc;
        return ergebnis;
    }

    static char[] h(char[] input) {
        char[] ergebnis = new char[4];
        for (int i = 0; i < 4; i++) {
            int zeile = (ergebnis[i] >> 4);
            int spalte = (ergebnis[i] & 0xF);
            ergebnis[i] = sBox[zeile][spalte];
        }
        return ergebnis;
    }
}
