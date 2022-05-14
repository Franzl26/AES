package AES;

import static AES.Funktionen.*;
import static AES.GaloisField.*;
import static AES.RoundKeyGen.*;
import static AES.Aes.*;

public class Schnittstelle {
    public static BitArray stringToBitArray(String string, int basis) {
        if (string == null) throw new IllegalArgumentException("String darf nicht null sein");
        if (basis == 2) return new BitArray(binString2arr(string));
        else if (basis == 16) return new BitArray(hexString2arr(string));
        else throw new IllegalArgumentException("Nur Basis 2 und 16 unterstützt");
    }

    public static BitArray hexStringToBitArray(String string) {
        if (string == null) throw new IllegalArgumentException("String darf nicht null sein");
        return new BitArray(hexString2arr(string));
    }

    public static BitArray binStringToBitArray(String string) {
        if (string == null) throw new IllegalArgumentException("String darf nicht null sein");
        return new BitArray(binString2arr(string));
    }

    public static char stringToChar(String string, int basis) {
        if (string == null) throw new IllegalArgumentException("String darf nicht null sein");
        if (basis == 2) return binString2char(string);
        else if (basis == 16) return hexString2char(string);
        else throw new IllegalArgumentException("Nur Basis 2 und 16 unterstützt");
    }

    public static String matrixToString(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Bytes lang sein");
        return matrix2String(matrix.getArray());
    }

    public static String charToString(char input, int basis) {
        if (basis == 2) return char2binString(input);
        else if (basis == 16) return char2hexString(input);
        else throw new IllegalArgumentException("Nur Basis 2 und 16 unterstützt");
    }

    public static String bitArrayToBinString(BitArray array) {
        if (array == null) throw new IllegalArgumentException("Array darf nicht null sein");
        return bitArrayToBinString(array, false);
    }

    public static String bitArrayToBinString(BitArray array, boolean byteTrenner) {
        if (array == null) throw new IllegalArgumentException("Array darf nicht null sein");
        return arr2binString(array.getArray(), byteTrenner);
    }

    public static String bitArrayToHexString(BitArray array) {
        if (array == null) throw new IllegalArgumentException("Array darf nicht null sein");
        return arr2hexString(array.getArray());
    }

    public static String bitArrayToHexString(BitArray array, boolean byteTrenner) {
        if (array == null) throw new IllegalArgumentException("Array darf nicht null sein");
        return arr2hexString(array.getArray(), byteTrenner);
    }

    public static BitArray encryptBlock(BitArray input, BitArray key) {
        if (input == null || key == null)
            throw new IllegalArgumentException("Die Matrix und der roundKey dürfen nicht null sein");
        if (input.length() != 16) throw new IllegalArgumentException("Der Input muss 16 Byte lang sein");
        return new BitArray(aesBlock(input.getArray(), key.getArray(), false));
    }

    public static BitArray decryptBlock(BitArray input, BitArray key) {
        if (input == null || key == null)
            throw new IllegalArgumentException("Die Matrix und der roundKey dürfen nicht null sein");
        if (input.length() != 16) throw new IllegalArgumentException("Der Input muss 16 Byte lang sein");
        return new BitArray(aesBlock(input.getArray(), key.getArray(), true));
    }

    public static void encryptFileWithCBC(String input, String output, BitArray key) {
        if (input == null || output == null || key == null)
            throw new IllegalArgumentException("Die Parameter dürfen nicht null sein");
        aesFileCBC(input, output, key.getArray(), false);
    }

    public static void encryptFileWithCBC(String input, String output, BitArray initVector, BitArray key) {
        if (input == null || output == null || key == null || initVector == null)
            throw new IllegalArgumentException("Die Parameter dürfen nicht null sein");
        aesFileCBCIV(input, output, key.getArray(), initVector.getArray(), false);
    }

    public static void decryptFileWithCBC(String input, String output, BitArray key) {
        if (input == null || output == null || key == null)
            throw new IllegalArgumentException("Die Parameter dürfen nicht null sein");
        aesFileCBC(input, output, key.getArray(), true);
    }

    public static void decryptFileWithCBC(String input, String output, BitArray initVector, BitArray key) {
        if (input == null || output == null || key == null)
            throw new IllegalArgumentException("Die Parameter dürfen nicht null sein");
        aesFileCBCIV(input, output, key.getArray(), initVector.getArray(), true);
    }

    public static RoundKeyGen getRoundKeyGenerator(BitArray key, boolean entschluesseln) {
        if (key == null) throw new IllegalArgumentException("Key darf nicht null sein");
        return new RoundKeyGen(key.getArray(), entschluesseln);
    }

    public static Aes getAESIterator(BitArray m, BitArray key, boolean entschluesseln) {
        if (key == null || m == null) throw new IllegalArgumentException("Key und m dürfen nicht null sein");
        return new Aes(m.getArray(), key.getArray(), entschluesseln);
    }

    public static BitArray doMatrixMultiVektor(BitArray vektor) {
        if (vektor == null) throw new IllegalArgumentException("Der Vektor darf nicht null sein");
        if (vektor.length() != 4) throw new IllegalArgumentException("Der Vektor muss 4 Byte lang sein");
        return new BitArray(matrixMul(vektor.getArray()));
    }

    public static BitArray doMatrixMultiVektorInverse(BitArray vektor) {
        if (vektor == null) throw new IllegalArgumentException("Der Vektor darf nicht null sein");
        if (vektor.length() != 4) throw new IllegalArgumentException("Der Vektor muss 4 Byte lang sein");
        return new BitArray(matrixMulInvers(vektor.getArray()));
    }

    public static BitArray doMixColum(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Die Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        mixColumn(tmp);
        return new BitArray(tmp);
    }

    public static BitArray doMixColumInverse(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Die Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        mixColumnInverse(tmp);
        return new BitArray(tmp);
    }

    public static BitArray doShiftRow(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Die Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        shiftRow(tmp);
        return new BitArray(tmp);
    }

    public static BitArray doShiftRowInverse(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Die Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        shiftRowInverse(tmp);
        return new BitArray(tmp);
    }

    public static BitArray doSubstituteByte(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Die Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        substituteByte(tmp);
        return new BitArray(tmp);
    }

    public static BitArray doSubstituteByteInverse(BitArray matrix) {
        if (matrix == null) throw new IllegalArgumentException("Die Matrix darf nicht null sein");
        if (matrix.length() != 16) throw new IllegalArgumentException("Die Matrix muss 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        substituteByteInverse(tmp);
        return new BitArray(tmp);
    }

    public static BitArray doAddRoundKey(BitArray matrix, BitArray roundKey) {
        if (matrix == null || roundKey == null)
            throw new IllegalArgumentException("Die Matrix und der roundKey dürfen nicht null sein");
        if (matrix.length() != 16 || roundKey.length() != 16)
            throw new IllegalArgumentException("Die Matrix und der roundKey müssen 16 Byte lang sein");
        char[] tmp = matrix.getArray().clone();
        addRoundKey(tmp, roundKey.getArray());
        return new BitArray(tmp);
    }

    public static BitArray doXOR(BitArray input1, BitArray input2) {
        if (input1 == null || input2 == null)
            throw new IllegalArgumentException("Die Parameter dürfen nicht null sein");
        if (input1.length() != input2.length())
            throw new IllegalArgumentException("Die Parameter müssen gleich lang sein");
        char[] tmp = input1.getArray().clone();
        xor(tmp, input2.getArray());
        return new BitArray(tmp);
    }

    public static BitArray aesRound(BitArray text, BitArray roundKey, int round, int roundMax, boolean entschluesseln) {
        if (text == null || roundKey == null) throw new IllegalArgumentException("Parameter dürfen nicht null sein");
        if (text.length() != 16 || roundKey.length() != 16)
            throw new IllegalArgumentException("text und roundKey müssen 16 Byte lang sein");
        if (round < 0 || roundMax < 0 || round > roundMax)
            throw new IllegalArgumentException("Parameter round/roundMax sind falsch");
        char[] tmp = text.getArray().clone();
        aesRoundEntsch(tmp, roundKey.getArray(), round, roundMax);
        if (entschluesseln) aesRoundEntsch(tmp, roundKey.getArray(), round, roundMax);
        else aesRoundVersch(tmp, roundKey.getArray(), round, roundMax);
        return new BitArray(tmp);
    }

    public static BitArray doG(BitArray input, int round) {
        if (round > 9) throw new IllegalArgumentException("Round darf maximal 9 sein");
        if (input == null) throw new IllegalArgumentException("Input darf nicht null sein");
        if (input.length() != 4) throw new IllegalArgumentException("Input muss 4 Bytes lang sein");
        return new BitArray(g(input.getArray(), getRC(round)));
    }

    public static BitArray doH(BitArray input) {
        if (input == null) throw new IllegalArgumentException("Input darf nicht null sein");
        if (input.length() != 4) throw new IllegalArgumentException("Input muss 4 Bytes lang sein");
        return new BitArray(h(input.getArray()));
    }

    public static BitArray[] getRoundKeys(BitArray key, boolean entschluesseln) {
        if (key == null) throw new IllegalArgumentException("Input darf nicht null sein");
        RoundKeyGen keyGen = new RoundKeyGen(key.getArray(), entschluesseln);
        int rounds = keyGen.getRoundMax();
        BitArray[] ergebnis = new BitArray[rounds];
        for (int i = 0; i < rounds; i++) {
            ergebnis[i] = new BitArray(keyGen.getNextKey());
        }
        return ergebnis;
    }

    public static char doGfMul(char input1, char input2) {
        if (input1 > 255 || input2 > 255)
            throw new IllegalArgumentException("Die Inputs dürfen maximal 8 Bit lang sein");
        return gfMul(input1, input2);
    }
}
