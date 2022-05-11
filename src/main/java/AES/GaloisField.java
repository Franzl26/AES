package AES;

class GaloisField {
    static char gfAdd(char in1, char in2) {
        return (char) (in1 ^ in2);
    }

    static char gfMul(char in1, char in2) {
        char ergebnis = 0;
        for (int i = 0; i < 8; i++) {
            if (((1 << i) & in1) != 0) {
                ergebnis ^= in2 << i;
            }
        }

        return gfReduce(ergebnis);
    }

    static char gfReduce(char input) {
        char ergebnis = input;
        for (int i = 14; i >= 8; i--) {
            if (((1 << i) & ergebnis) != 0) {
                ergebnis ^= 0b100011011 << (i - 8);
            }
        }
        return ergebnis;
    }

    static char[] matrixMul(char[] inp) {
        char[][] mat = {
                {2, 3, 1, 1},
                {1, 2, 3, 1},
                {1, 1, 2, 3},
                {3, 1, 1, 2},
        };
        char[] ergebnis = new char[4];
        for (int zeile = 0; zeile < 4; zeile++) {
            for (int i = 0; i < 4; i++) {
                int faktor = mat[zeile][i];
                if (faktor == 3) {
                    ergebnis[zeile] ^= inp[i];
                    ergebnis[zeile] ^= inp[i] << 1;
                } else {
                    ergebnis[zeile] ^= inp[i] << (faktor - 1);
                }
            }
            if ((ergebnis[zeile] & 0x100) != 0) ergebnis[zeile] ^= 0b100011011;
        }
        return ergebnis;
    }

    static char[] matrixMulInvers(char[] inp) {
        char[][] mat = {
                {0xE, 0xB, 0xD, 0x9},
                {0x9, 0xE, 0xB, 0xD},
                {0xD, 0x9, 0xE, 0xB},
                {0xB, 0xD, 0x9, 0xE}
        };
        char[] ergebnis = new char[4];
        for (int zeile = 0; zeile < 4; zeile++) {
            for (int i = 0; i < 4; i++) {
                ergebnis[zeile] ^= gfMul(inp[i], mat[zeile][i]);
            }
        }
        return ergebnis;
    }
}
