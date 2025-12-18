import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Camellia {
    final private int[][] SBOX1 = {{112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65},
            {35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189},
            {134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26},
            {166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77},
            {139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153},
            {223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215},
            {20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34},
            {254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80},
            {170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210},
            {16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148},
            {135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226},
            {82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46},
            {233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89},
            {120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250},
            {114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164},
            {64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158}};
    final private long[] SIGMA = {0xA09E667F3BCC908BL, 0xB67AE8584CAA73B2L, 0xC6EF372FE94F82BEL,
            0x54FF53A5F1D36F1CL, 0x10E527FADE682D1DL, 0xB05688C2B3E6C1FDL};

    private static final int SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 100000;

    private byte cycleShift(byte value, int count) {
        int temp = (value & 0xFF) >> (8 - count);
        return (byte) ((value << count) + temp);
    }
    private int cycleShift(int value, int count) {
        int temp = (value) >>> (32 - count);
        return ((value << count) + temp);
    }
    private long[] cycleShiftForPair(long[] values, int count) {
        long[] temp = new long[2];
        long[] new_values = new long[2];
        if (count <= 64) {
            temp[1] = (values[0] >>> (64 - count));
            new_values[0] = (values[0] << count) + (values[1] >>> (64 - count));
            new_values[1] = (values[1] << count) + temp[1];
        } else {
            temp[0] = values[0] >>> (64 - (count - 64));
            temp[1] = (values[0] << (count - 64)) + (values[1] >>> (64 - (count - 64)));
            new_values[0] = (values[1] << (64 - (128 - count))) + temp[0];
            new_values[1] = temp[1];
        }
        return new_values;
    }
    private long FFunc(long data, long subkey) {
        long x = data ^ subkey, result = 0;
        byte[] t = new byte[8];
        byte[] y = new byte[8];
        t[0] = (byte) (x >> 56);
        t[1] = (byte) (x >> 48);
        t[2] = (byte) (x >> 40);
        t[3] = (byte) (x >> 32);
        t[4] = (byte) (x >> 24);
        t[5] = (byte) (x >> 16);
        t[6] = (byte) (x >> 8);
        t[7] = (byte) x;
        t[0] = (byte) SBOX1[(t[0] >> 4) & 0x0F][t[0] & 0x0F];
        t[1] = cycleShift((byte) SBOX1[(t[1] >> 4) & 0x0F][t[1] & 0x0F], 1);
        t[2] = cycleShift((byte) SBOX1[(t[2] >> 4) & 0x0F][t[2] & 0x0F], 7);
        t[3] = (byte) SBOX1[(cycleShift(t[3], 1) >> 4) & 0x0F][cycleShift(t[3], 1) & 0x0F];
        t[4] = cycleShift((byte) SBOX1[(t[4] >> 4) & 0x0F][t[4] & 0x0F], 1);
        t[5] = cycleShift((byte) SBOX1[(t[5] >> 4) & 0x0F][t[5] & 0x0F], 7);
        t[6] = (byte) SBOX1[(cycleShift(t[6], 1) >> 4) & 0x0F][cycleShift(t[6], 1) & 0x0F];
        t[7] = (byte) SBOX1[(t[7] >> 4) & 0x0F][t[7] & 0x0F];
        y[0] = (byte) (t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7]);
        y[1] = (byte) (t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7]);
        y[2] = (byte) (t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7]);
        y[3] = (byte) (t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6]);
        y[4] = (byte) (t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7]);
        y[5] = (byte) (t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7]);
        y[6] = (byte) (t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7]);
        y[7] = (byte) (t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6]);
        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result += y[i] & 0xFF;
        }
        return result;
    }
    private long FLFunc(long data, long subkey) {
        int x1 = (int) (data >>> 32);
        int x2 = (int) (data & 0xFFFFFFFFL);
        int k1 = (int) (subkey >>> 32);
        int k2 = (int) (subkey & 0xFFFFFFFFL);
        x2 = x2 ^ (cycleShift((x1 & k1), 1));
        x1 = x1 ^ (x2 | k2);
        return ((long) x1 << 32) | (x2 & 0xFFFFFFFFL);
    }
    private long FLINVFunc(long data, long subkey) {
        int y1 = (int) (data >>> 32);
        int y2 = (int) (data & 0xFFFFFFFFL);
        int k1 = (int) (subkey >>> 32);
        int k2 = (int) (subkey & 0xFFFFFFFFL);
        y1 = y1 ^ (y2 | k2);
        y2 = y2 ^ (cycleShift((y1 & k1), 1));
        return ((long) y1 << 32) | (y2 & 0xFFFFFFFFL);
    }
    private long[] getKLKRByte(byte[] byte_key) {
        long[] key = new long[4];
        int c = -1;
        if (byte_key.length != 16 && byte_key.length != 24 && byte_key.length != 32) {
            throw new IllegalArgumentException("Недопустимая длина ключа Camellia");
        }
        for (int i = 0; i < (Math.min(byte_key.length, 32)); i++) {
            if (i % 8 == 0) c++;
            key[c] <<= 8;
            key[c] += byte_key[i] & 0xFF;
        }
        if (byte_key.length == 24)
            key[3] = ~key[2];
        return key;
    }
    private long[] getKAKB(long[] KL_KR) {
        long[] KA_KB = new long[4];
        long D1 = KL_KR[0] ^ KL_KR[2];
        long D2 = KL_KR[1] ^ KL_KR[3];
        D2 = D2 ^ FFunc(D1, SIGMA[0]);
        D1 = D1 ^ FFunc(D2, SIGMA[1]);
        D1 = D1 ^ KL_KR[0];
        D2 = D2 ^ KL_KR[1];
        D2 = D2 ^ FFunc(D1, SIGMA[2]);
        D1 = D1 ^ FFunc(D2, SIGMA[3]);
        KA_KB[0] = D1;
        KA_KB[1] = D2;
        D1 = KA_KB[0] ^ KL_KR[2];
        D2 = KA_KB[1] ^ KL_KR[3];
        D2 = D2 ^ FFunc(D1, SIGMA[4]);
        D1 = D1 ^ FFunc(D2, SIGMA[5]);
        KA_KB[2] = D1;
        KA_KB[3] = D2;
        return KA_KB;
    }
    private long[] getSubkeys128(long[] KL_KR, long[] KA_KB) {
        long[] KL = {KL_KR[0], KL_KR[1]}, KA = {KA_KB[0], KA_KB[1]};
        long[] subkeys = new long[26];
        subkeys[0] = KL[0]; subkeys[1] = KL[1]; subkeys[2] = KA[0]; subkeys[3] = KA[1];
        subkeys[4] = cycleShiftForPair(KL, 15)[0]; subkeys[5] = cycleShiftForPair(KL, 15)[1];
        subkeys[6] = cycleShiftForPair(KA, 15)[0]; subkeys[7] = cycleShiftForPair(KA, 15)[1];
        subkeys[8] = cycleShiftForPair(KA, 30)[0]; subkeys[9] = cycleShiftForPair(KA, 30)[1];
        subkeys[10] = cycleShiftForPair(KL, 45)[0]; subkeys[11] = cycleShiftForPair(KL, 45)[1];
        subkeys[12] = cycleShiftForPair(KA, 45)[0]; subkeys[13] = cycleShiftForPair(KL, 60)[1];
        subkeys[14] = cycleShiftForPair(KA, 60)[0]; subkeys[15] = cycleShiftForPair(KA, 60)[1];
        subkeys[16] = cycleShiftForPair(KL, 77)[0]; subkeys[17] = cycleShiftForPair(KL, 77)[1];
        subkeys[18] = cycleShiftForPair(KL, 94)[0]; subkeys[19] = cycleShiftForPair(KL, 94)[1];
        subkeys[20] = cycleShiftForPair(KA, 94)[0]; subkeys[21] = cycleShiftForPair(KA, 94)[1];
        subkeys[22] = cycleShiftForPair(KL, 111)[0]; subkeys[23] = cycleShiftForPair(KL, 111)[1];
        subkeys[24] = cycleShiftForPair(KA, 111)[0]; subkeys[25] = cycleShiftForPair(KA, 111)[1];
        return subkeys;
    }
    private long[] getSubkeys192_256(long[] KL_KR, long[] KA_KB) {
        long[] KL = {KL_KR[0], KL_KR[1]}, KR = {KL_KR[2], KL_KR[3]};
        long[] KA = {KA_KB[0], KA_KB[1]}, KB = {KA_KB[2], KA_KB[3]};
        long[] subkeys = new long[34];
        subkeys[0] = KL[0]; subkeys[1] = KL[1]; subkeys[2] = KB[0]; subkeys[3] = KB[1];
        subkeys[4] = cycleShiftForPair(KR, 15)[0]; subkeys[5] = cycleShiftForPair(KR, 15)[1];
        subkeys[6] = cycleShiftForPair(KA, 15)[0]; subkeys[7] = cycleShiftForPair(KA, 15)[1];
        subkeys[8] = cycleShiftForPair(KR, 30)[0]; subkeys[9] = cycleShiftForPair(KR, 30)[1];
        subkeys[10] = cycleShiftForPair(KB, 30)[0]; subkeys[11] = cycleShiftForPair(KB, 30)[1];
        subkeys[12] = cycleShiftForPair(KL, 45)[0]; subkeys[13] = cycleShiftForPair(KL, 45)[1];
        subkeys[14] = cycleShiftForPair(KA, 45)[0]; subkeys[15] = cycleShiftForPair(KA, 45)[1];
        subkeys[16] = cycleShiftForPair(KL, 60)[0]; subkeys[17] = cycleShiftForPair(KL, 60)[1];
        subkeys[18] = cycleShiftForPair(KR, 60)[0]; subkeys[19] = cycleShiftForPair(KR, 60)[1];
        subkeys[20] = cycleShiftForPair(KB, 60)[0]; subkeys[21] = cycleShiftForPair(KB, 60)[1];
        subkeys[22] = cycleShiftForPair(KL, 77)[0]; subkeys[23] = cycleShiftForPair(KL, 77)[1];
        subkeys[24] = cycleShiftForPair(KA, 77)[0]; subkeys[25] = cycleShiftForPair(KA, 77)[1];
        subkeys[26] = cycleShiftForPair(KR, 94)[0]; subkeys[27] = cycleShiftForPair(KR, 94)[1];
        subkeys[28] = cycleShiftForPair(KA, 94)[0]; subkeys[29] = cycleShiftForPair(KA, 94)[1];
        subkeys[30] = cycleShiftForPair(KL, 111)[0]; subkeys[31] = cycleShiftForPair(KL, 111)[1];
        subkeys[32] = cycleShiftForPair(KB, 111)[0]; subkeys[33] = cycleShiftForPair(KB, 111)[1];
        return subkeys;
    }
    private long[] transformKeys128(long[] subkeys) {
        long[] new_subkeys = new long[subkeys.length];
        new_subkeys[0] = subkeys[24];
        new_subkeys[1] = subkeys[25];
        new_subkeys[24] = subkeys[0];
        new_subkeys[25] = subkeys[1];
        for (int i = 2; i <= 12; i++) {
            new_subkeys[i] = subkeys[25 - i];
            new_subkeys[25 - i] = subkeys[i];
        }
        return new_subkeys;
    }
    private long[] transformKeys192_256(long[] subkeys) {
        long[] new_subkeys = new long[subkeys.length];
        new_subkeys[0] = subkeys[32];
        new_subkeys[1] = subkeys[33];
        new_subkeys[32] = subkeys[0];
        new_subkeys[33] = subkeys[1];
        for (int i = 2; i <= 16; i++) {
            new_subkeys[i] = subkeys[33 - i];
            new_subkeys[33 - i] = subkeys[i];
        }
        return new_subkeys;
    }
    protected long[] keySchedule(byte[] byte_key) {
        long[] KL_KR = getKLKRByte(byte_key);
        long[] KA_KB = getKAKB(KL_KR);
        long[] subkeys = (byte_key.length <= 16) ? getSubkeys128(KL_KR, KA_KB) : getSubkeys192_256(KL_KR, KA_KB);
        return subkeys;
    }
    protected long[] crypt(long D1, long D2, long[] subkeys) {
        int size = subkeys.length;
        D1 = D1 ^ subkeys[0];
        D2 = D2 ^ subkeys[1];
        for (int i = 2; i < size - 2; i += 2) {
            if (i % 8 == 0) {
                D1 = FLFunc(D1, subkeys[i]);
                D2 = FLINVFunc(D2, subkeys[i + 1]);
            } else {
                D2 = D2 ^ FFunc(D1, subkeys[i]);
                D1 = D1 ^ FFunc(D2, subkeys[i + 1]);
            }
        }
        D2 = D2 ^ subkeys[size - 2];
        D1 = D1 ^ subkeys[size - 1];
        return new long[]{D2, D1};
    }
    private byte[][] longToByte(long D1, long D2) {
        byte[][] bytes = new byte[2][8];
        for (int i = 7; i >= 0; i--) {
            bytes[0][i] = (byte) D1;
            bytes[1][i] = (byte) D2;
            D1 >>>= 8;
            D2 >>>= 8;
        }
        return bytes;
    }
    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    private byte[] deriveKey(String password, byte[] salt, int keyLengthBits) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, keyLengthBits);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка генерации ключа", e);
        }
    }
    private void encryptECB(String path, String password) throws Exception {
        byte[] salt = generateSalt();
        byte[] key = deriveKey(password, salt, 256);

        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        fis.close();

        int pad = 16 - (data.length % 16);
        if (pad == 16) pad = 0;
        byte[] padded = Arrays.copyOf(data, data.length + (pad == 0 ? 16 : pad));
        Arrays.fill(padded, data.length, padded.length, (byte) (pad == 0 ? 16 : pad));

        long[] ks = keySchedule(key);

        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(path + ".ecb"))) {
            out.write(salt);
            for (int i = 0; i < padded.length; i += 16) {
                long D1 = ByteBuffer.wrap(Arrays.copyOfRange(padded, i, i + 8)).getLong();
                long D2 = ByteBuffer.wrap(Arrays.copyOfRange(padded, i + 8, i + 16)).getLong();
                long[] res = crypt(D1, D2, ks);
                byte[][] b = longToByte(res[0], res[1]);
                out.write(b[0]);
                out.write(b[1]);
            }
        }
    }

    private void decryptECB(String path, String password) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        byte[] fileData = new byte[fis.available()];
        fis.read(fileData);
        fis.close();

        if (fileData.length < SALT_LENGTH) throw new IOException("Файл повреждён: нет соли");
        byte[] salt = Arrays.copyOfRange(fileData, 0, SALT_LENGTH);
        byte[] cipher = Arrays.copyOfRange(fileData, SALT_LENGTH, fileData.length);

        byte[] key = deriveKey(password, salt, 256);
        long[] ks = transformKeys192_256(keySchedule(key));
        byte[] plain = new byte[cipher.length];

        for (int i = 0; i < cipher.length; i += 16) {
            long D1 = ByteBuffer.wrap(Arrays.copyOfRange(cipher, i, i + 8)).getLong();
            long D2 = ByteBuffer.wrap(Arrays.copyOfRange(cipher, i + 8, i + 16)).getLong();
            long[] res = crypt(D1, D2, ks);
            byte[][] b = longToByte(res[0], res[1]);
            System.arraycopy(b[0], 0, plain, i, 8);
            System.arraycopy(b[1], 0, plain, i + 8, 8);
        }

        int pad = plain[plain.length - 1] & 0xFF;
        if (pad < 1 || pad > 16) pad = 0;

        String out = path.endsWith(".ecb") ? path.substring(0, path.length() - 4) + ".dec" : path + ".dec";

        FileOutputStream fos = new FileOutputStream(out);
        fos.write(Arrays.copyOf(plain, plain.length - pad));
        fos.close();
    }

    private void encryptOFB(String path, String password) throws Exception {
        byte[] salt = generateSalt();
        byte[] key = deriveKey(password, salt, 256);

        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        fis.close();

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        long[] ks = keySchedule(key);
        long D1 = ByteBuffer.wrap(Arrays.copyOfRange(iv, 0, 8)).getLong();
        long D2 = ByteBuffer.wrap(Arrays.copyOfRange(iv, 8, 16)).getLong();

        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(path + ".ofb"))) {
            out.write(salt);
            out.write(iv);
            for (int i = 0; i < data.length; i += 16) {
                long[] ksBlock = crypt(D1, D2, ks);
                byte[][] ksb = longToByte(ksBlock[0], ksBlock[1]);
                byte[] ksFull = new byte[16];
                System.arraycopy(ksb[0], 0, ksFull, 0, 8);
                System.arraycopy(ksb[1], 0, ksFull, 8, 8);
                int len = Math.min(16, data.length - i);
                for (int j = 0; j < len; j++) {
                    out.write(data[i + j] ^ ksFull[j]);
                }
                D1 = ksBlock[0];
                D2 = ksBlock[1];
            }
        }
    }

    private void decryptOFB(String path, String password) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        byte[] fileData = new byte[fis.available()];
        fis.read(fileData);
        fis.close();

        if (fileData.length < SALT_LENGTH + 16) throw new IOException("Файл повреждён: нет соли или IV");
        byte[] salt = Arrays.copyOfRange(fileData, 0, SALT_LENGTH);
        byte[] iv = Arrays.copyOfRange(fileData, SALT_LENGTH, SALT_LENGTH + 16);
        byte[] cipher = Arrays.copyOfRange(fileData, SALT_LENGTH + 16, fileData.length);

        byte[] key = deriveKey(password, salt, 256);
        long[] ks = keySchedule(key);
        long D1 = ByteBuffer.wrap(Arrays.copyOfRange(iv, 0, 8)).getLong();
        long D2 = ByteBuffer.wrap(Arrays.copyOfRange(iv, 8, 16)).getLong();
        byte[] plain = new byte[cipher.length];

        for (int i = 0; i < cipher.length; i += 16) {
            long[] ksBlock = crypt(D1, D2, ks);
            byte[][] ksb = longToByte(ksBlock[0], ksBlock[1]);
            byte[] ksFull = new byte[16];
            System.arraycopy(ksb[0], 0, ksFull, 0, 8);
            System.arraycopy(ksb[1], 0, ksFull, 8, 8);
            int len = Math.min(16, cipher.length - i);
            for (int j = 0; j < len; j++) {
                plain[i + j] = (byte) (cipher[i + j] ^ ksFull[j]);
            }
            D1 = ksBlock[0];
            D2 = ksBlock[1];
        }

        String out = path.endsWith(".ofb") ? path.substring(0, path.length() - 4) + ".dec" : path + ".dec";

        FileOutputStream fos = new FileOutputStream(out);
        fos.write(plain);
        fos.close();
    }

    public void EncryptECB(String[] paths, String password) {
        for (String path : paths) processPath(path, password, "ECB", true);
    }
    public void DecryptECB(String[] paths, String password) {
        for (String path : paths) processPath(path, password, "ECB", false);
    }
    public void EncryptOFB(String[] paths, String password) {
        for (String path : paths) processPath(path, password, "OFB", true);
    }
    public void DecryptOFB(String[] paths, String password) {
        for (String path : paths) processPath(path, password, "OFB", false);
    }

    private void processPath(String path, String password, String mode, boolean encrypt) {
        Path p = Paths.get(path);
        if (!Files.exists(p)) {
            System.err.println("Путь не существует: " + path);
            return;
        }
        if (Files.isDirectory(p)) {
            try {
                Files.walkFileTree(p, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (!Files.isDirectory(file)) {
                            handleFile(file.toString(), password, mode, encrypt);
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException e) {
                System.err.println("Ошибка при обходе директории: " + path);
                e.printStackTrace();
            }
        } else {
            handleFile(path, password, mode, encrypt);
        }
    }

    private void handleFile(String path, String password, String mode, boolean encrypt) {
        try {
            if (encrypt) {
                if ("ECB".equals(mode)) {
                    encryptECB(path, password);
                } else if ("OFB".equals(mode)) {
                    encryptOFB(path, password);
                }
            } else {
                if (("ECB".equals(mode) && path.endsWith(".ecb")) ||
                        ("OFB".equals(mode) && path.endsWith(".ofb"))) {
                    if ("ECB".equals(mode)) {
                        decryptECB(path, password);
                    } else {
                        decryptOFB(path, password);
                    }
                } else {
                    System.err.println("Файл не подходит для расшифровки в режиме " + mode + ": " + path);
                }
            }
        } catch (Exception e) {
            System.err.println("Ошибка при обработке " + path + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    public byte[] encryptBlockForTest(byte[] plaintext, byte[] key) {
        long D1 = ByteBuffer.wrap(plaintext, 0, 8).getLong();
        long D2 = ByteBuffer.wrap(plaintext, 8, 8).getLong();
        long[] ks = keySchedule(key);
        long[] res = crypt(D1, D2, ks);
        byte[][] b = longToByte(res[0], res[1]);
        byte[] out = new byte[16];
        System.arraycopy(b[0], 0, out, 0, 8);
        System.arraycopy(b[1], 0, out, 8, 8);
        return out;
    }
    public byte[] computeSHA256(String filepath) {
        try {
            FileInputStream fis = new FileInputStream(filepath);
            byte[] data = new byte[fis.available()];
            fis.read(data);
            fis.close();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            System.err.println("Ошибка SHA-256 для: " + filepath);
            return null;
        }
    }

    public boolean verifySHA256(String file1, String file2) {
        byte[] h1 = computeSHA256(file1);
        byte[] h2 = computeSHA256(file2);
        return h1 != null && h2 != null && MessageDigest.isEqual(h1, h2);
    }
}