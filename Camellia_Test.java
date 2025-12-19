import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Camellia_Test {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Использование:");
            System.err.println("  java Camellia_Test <пароль> <режим: ECB|OFB> <путь...>");
            System.exit(1);
        }

        String password = args[0];
        String mode = args[1].toUpperCase();
        if (!"ECB".equals(mode) && !"OFB".equals(mode)) {
            System.err.println("Режим должен быть 'ECB' или 'OFB'");
            System.exit(1);
        }

        String[] inputPaths = Arrays.copyOfRange(args, 2, args.length);

        System.out.println("Проверка контрольных значений...");
        RFCTests();
        System.out.println("Контрольные значения совпали.\n");

        Camellia cipher = new Camellia();
        List<String> allFiles = collectFiles(inputPaths);

        for (String path : allFiles) {
            try {
                long size = Files.size(Paths.get(path));
                System.out.printf("Файл: %s (%d байт)\n", path, size);

                if ("ECB".equals(mode)) {
                    cipher.EncryptECB(new String[]{path}, password);
                    cipher.DecryptECB(new String[]{path + ".ecb"}, password);
                } else {
                    cipher.EncryptOFB(new String[]{path}, password);
                    cipher.DecryptOFB(new String[]{path + ".ofb"}, password);
                }

                String decPath = path + ".dec";
                boolean ok = cipher.verifySHA256(path, decPath);
                System.out.println(" Полученный результат: " + (ok ? "OK" : "FAIL"));
                System.out.println();
            } catch (Exception e) {
                System.err.println("Ошибка при обработке " + path + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private static void RFCTests() {
        Camellia cam = new Camellia();
        boolean allPassed = true;

        // 128-бит
        byte[] k128 = hex("0123456789abcdef fedcba9876543210");
        byte[] pt = hex("0123456789abcdef fedcba9876543210");
        byte[] ct128 = hex("6767313854966973 0857065648eabe43");
        allPassed &= test(cam, k128, pt, ct128, "128-bit");

        // 192-бит
        byte[] k192 = hex("0123456789abcdef fedcba9876543210 0011223344556677");
        byte[] ct192 = hex("b4993401b3e996f8 4ee5cee7d79b09b9");
        allPassed &= test(cam, k192, pt, ct192, "192-bit");

        // 256-бит
        byte[] k256 = hex("0123456789abcdef fedcba9876543210 0011223344556677 8899aabbccddeeff");
        byte[] ct256 = hex("9acc237dff16d76c 20ef7c919e3a7509");
        allPassed &= test(cam, k256, pt, ct256, "256-bit");

        if (!allPassed) {
            System.err.println("Тест контрольных значений не пройден");
            System.exit(1);
        }
    }

    private static boolean test(Camellia c, byte[] key, byte[] pt, byte[] ciphertext, String name) {
        byte[] result = c.encryptBlockForTest(pt, key);
        boolean mark = Arrays.equals(result, ciphertext);
        System.out.println(name + ": " + (mark ? "OK" : "FAIL"));
        if (!mark) {
            System.out.println("  Ожидалось: " + bytesToHex(ciphertext));
            System.out.println("  Получено:  " + bytesToHex(result));
        }
        return mark;
    }

    private static byte[] hex(String s) {
        s = s.replaceAll("\\s+", "");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x ", b));
        return sb.toString().trim();
    }

    private static List<String> collectFiles(String[] paths) {
        List<String> files = new ArrayList<>();
        for (String p : paths) {
            walkFiles(Paths.get(p), files);
        }
        return files;
    }

    private static void walkFiles(Path root, List<String> result) {
        if (!Files.exists(root)) {
            System.err.println("Путь не существует: " + root);
            return;
        }
        if (Files.isRegularFile(root)) {
            result.add(root.toString());
        } else if (Files.isDirectory(root)) {
            try {
                Files.walk(root)
                        .filter(path -> Files.isRegularFile(path))
                        .forEach(p -> result.add(p.toString()));
            } catch (Exception e) {
                System.err.println("Ошибка обхода директории: " + root);
                e.printStackTrace();
            }
        }
    }
}
