package AES;

import static AES.Funktionen.*;
import static AES.GaloisField.*;
import static AES.KeyGen.*;
import static AES.Aes.*;

public class Schnittstelle {
    public static BitArray hexStringToBitArray(String string) {
        if (string == null) throw new IllegalArgumentException("String darf nicht null sein");
        return new BitArray(hexString2arr(string));
    }

    public static BitArray binStringToBitArray(String string) {
        if (string == null) throw new IllegalArgumentException("String darf nicht null sein");
        return new BitArray(binString2arr(string));
    }

    public static String bitArrayToBinString(BitArray array) {
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

    public static KeyGen getKeyGenerator(String key, boolean entschluesseln) {
        return getKeyGenerator(hexStringToBitArray(key), entschluesseln);
    }

    public static KeyGen getKeyGenerator(BitArray key, boolean entschluesseln) {
        return new KeyGen(key.getArray(), entschluesseln);
    }

    public static Aes getAESIterator(String m, String key, boolean entschluesseln) {
        return getAESIterator(hexStringToBitArray(m), hexStringToBitArray(key), entschluesseln);
    }

    public static Aes getAESIterator(BitArray m, BitArray key, boolean entschluesseln) {
        return new Aes(m.getArray(), key.getArray(), entschluesseln);
    }


}
