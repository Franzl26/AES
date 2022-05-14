package AES;

import static AES.Funktionen.*;

public class BitArray {
    private char[] array;

    BitArray(char[] array) {
        this.array = array;
    }

    public char[] getArray() {
        return array;
    }

    public int length() {
        return array.length;
    }

    @Override
    public String toString() {
        return arr2hexString(array, false);
    }

    public String toString(int basis) {
        return toString(basis, false);
    }

    public String toString(int basis, boolean byteTrenner) {
        if (basis != 2 && basis != 16)
            throw new UnsupportedOperationException("Es könne nur Strings mit der Basis 2 oder 16 erzeugt werden");
        if (basis == 2) return arr2binString(array, byteTrenner);
        else return arr2hexString(array, byteTrenner);
    }
}
