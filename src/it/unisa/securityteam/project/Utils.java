package it.unisa.securityteam.project;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Utils {
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

}
