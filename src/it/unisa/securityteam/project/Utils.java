package it.unisa.securityteam.project;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Utils {

    private static final String dirName = "/home/apaolillo/NetBeansProjects/ProjectCyberSecurity/src";

    private static String digits = "0123456789abcdef";

    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static SecretKey createKeyForAES(int bitLength, SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");

        generator.init(128, random);

        return generator.generateKey();
    }

    public static IvParameterSpec createCtrIvForAES(
            SecureRandom random) {
        byte[] ivBytes = new byte[16];

        // initially randomize
        random.nextBytes(ivBytes);

        // set the counter bytes to 0
        for (int i = 0; i != 8; i++) {
            ivBytes[8 + i] = 0;
        }

        return new IvParameterSpec(ivBytes);
    }

    public static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(byte[] bytes, int from, int length) {
        char[] chars = new char[length];

        for (int i = from; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    public static byte[] toByteArray(String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    public static HashMap<String, String> readFile(String filename) {
        File file = new File(dirName, filename);
        HashMap<String, String> map = new HashMap<>();
        try ( Scanner sc = new Scanner(new BufferedReader(new FileReader(file)))) {
            sc.useLocale(Locale.US);
            sc.useDelimiter("\\s");
            while (sc.hasNext()) {
                map.put(sc.next(), sc.next());
            }
        } catch (FileNotFoundException ex) {
            System.err.println("FileNotFound Error");
        }
        return map;
    }

    public static String createStringPKElGamal(ElGamalPK PK) {
        return new String(PK.getP() + "," + PK.getQ() + "," + PK.getG() + "," + PK.getH());
    }

    public static String createStringCTElGamal(ElGamalCT CT) {
        return new String(CT.getC() + "," + CT.getC2());
    }

    public static void writeResult(String filename, BigInteger resultVoting) {
        File file = new File(dirName, filename);
        try ( BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
            if (resultVoting.compareTo(BigInteger.ZERO) == 1) {
                out.write("The yes won the referendum.\nResult: " + resultVoting.toString() + " yes");
            } else if (resultVoting.compareTo(BigInteger.ZERO) == 0) {
                out.write("The referendum did not have a majority\n + Result: " + resultVoting.toString());
            } else {

                out.write("The no won the referendum.\nResult: " + resultVoting.abs().toString() + " no");
            }
        } catch (IOException ex) {
            System.err.println("Error in writeFileResult");
        }
    }

}
