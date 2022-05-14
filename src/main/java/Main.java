import AES.Aes;
import AES.BitArray;
import AES.RoundKeyGen;

import static AES.Schnittstelle.*;

public class Main {
    public static void main(String[] args) {
        beispiele();
        uebung();
    }

    public static void beispiele() {
        // Daten/Bit-String werden in BitArrays zwischengespeichert
        BitArray key;
        BitArray message;
        // Daten können entweder als Binär- oder als Hexadezimal-String eingegeben werden
        // dabei sind auch Leerzeichen zugelassen, bei Hex ist groß und klein erlaubt
        // nur Eingaben ganzer Bytes sind erlaubt, sonst kommt eine Fehlermeldung
        key = hexStringToBitArray("0123456789abcdef 0123456789abcdef");
        message = binStringToBitArray("00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111 00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111");

        // der Typ BitArray wird automatisch in einen Hex-String umgewandelt
        // alternativ kann toString oder bitArrayToBinString/bitArrayToHexString aufgerufen werden
        // hierbei können auch für die bessere Lesbarkeit Byte-Trenner aktiviert werden
        System.out.println("key: " + key);
        System.out.println("key: " + key.toString(16, true));
        System.out.println("key: " + key.toString(2));
        System.out.println("key: " + bitArrayToHexString(key));
        System.out.println("key: " + bitArrayToBinString(key, true));
        // wie bei AES üblich kann das BitArray auch als 4x4 Byte-Matrix dargestellt werden
        System.out.println("message:\n" + matrixToString(message));

        // Inputs für die einzelnen Funktionen sind BitArrays
        // sollten die Längen der Inputs nicht stimmen, wird eine entsprechende Exception geworfen (hoffentlich)
        BitArray cipher = encryptBlock(message, key);
        System.out.println("cipher: " + cipher);

        // Außerdem können RoundKey- und AES-Iteratoren erzeugt werden
        // diese liefern dann bei jedem Aufruf den nächsten Rundenschlüssel/das Ergebnis der nächsten Runde
        Aes aesIt = getAESIterator(message, key, false);
        RoundKeyGen keyGen = getRoundKeyGenerator(key, false);
        for (int i = 0; i <= keyGen.getRoundMax(); i++) {
            System.out.println("Runde " + i + " key: " + keyGen.nextKey()
                    + ", Rundenergebnis: " + aesIt.nextRound());
        }

        // außerdem können mit do... alle Schritte einzeln durchgeführt werden
        // dabei sind die Eingabelängen zu beachten, die aber ggf. eine passende Exception werfen sollten
        BitArray show = doG(hexStringToBitArray("12345678"), 1);
        show = doMixColum(hexStringToBitArray("12345678 90abcdef 87654321 fedcba09"));

        // außerdem gehen noch ein paar andere tolle Dinge für die es keine Beispiele gibt
    }

    public static void uebung() {
        // 8
        System.out.println("8: " + charToString(doGfMul(stringToChar("11001011", 2), stringToChar("00110101", 2)), 2));
        // 9
        System.out.println("9: " + bitArrayToHexString(doMatrixMultiVektor(hexStringToBitArray("02 03 05 01"))));
        // 10 a
        BitArray input = hexStringToBitArray("05 13 36 28 87 5a 30 8d 31 a2 98 a2 e0 37 07 35");
        input = doSubstituteByte(input);
        System.out.println("10a:\n" + matrixToString(input));
        // b
        input = hexStringToBitArray("6B 1A 05 34 C4 BE 04 5D C7 C7 46 3A E1 9A C5 18");
        input = doShiftRow(input);
        System.out.println("10b:\n" + matrixToString(input));
        //c
        System.out.println("10c: " + bitArrayToHexString(doMatrixMultiVektor(hexStringToBitArray("6b be 46 18")), true));
    }
}
