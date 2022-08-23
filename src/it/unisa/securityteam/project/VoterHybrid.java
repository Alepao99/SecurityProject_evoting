/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.Decrypt;
import static it.unisa.securityteam.project.ElGamal.Encrypt;
import static it.unisa.securityteam.project.ElGamal.Setup;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author apaolillo
 */
public class VoterHybrid { // hybrid encryption: El Gamal + CBC-AES

    private static final SecureRandom sc = new SecureRandom();

    public static void main(String[] args) throws IOException {
        String msg = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa11111111111112222222222222222266666666666666666666666666"; //string to encrypt

        //SecureRandom sc = new SecureRandom(); // initialize random source
        //Setup
        ElGamalSK SK = Setup(64); // Setup El Gamal - in a real implementation it is suggested to choose at least 2048 bits of security. 
        // We keep a low security parameter to execute the program fastly during the test

        byte[] ivBytes = new byte[16]; // create an IV for AES in CBC mode
        sc.nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        //
        // Encryption
        //
        BigInteger M; // set M to a random message in the message space of El Gamal

        M = new BigInteger(SK.getPK().getSecurityparameter(), sc);
        M = M.mod(SK.getPK().getP());

        ElGamalCT CT = Encrypt(SK.getPK(), M); // Encrypt M with El Gamal
        try {
            // hash M to a byte array and put the result in keyBytes that will be used to generate a key for AES128
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update(M.toByteArray());
            byte[] keyBytes = h.digest(); // keyBytes=Hash(M)
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); // use keyBytes to generate an AES key

            byte[] input = msg.getBytes(); // convert the msg string to a byte array that will be encrypted under CBC-AES

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  // encrypt array input under the key derived from M at previous steps
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);
            // cipherText encrypts the byte array input under the key derived from M

            // decryption 
            M = Decrypt(CT, SK); // decrypt M 

            h.update(M.toByteArray()); // derive the AES key from M
            keyBytes = h.digest();
            key = new SecretKeySpec(keyBytes, "AES"); // key is Hash(M)

            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            // decrypt the plaintext using the AES key computed before
            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);
            System.out.println("plain : " + toString(plainText, ptLength)
                    + " bytes: " + ptLength);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String toString(
            byte[] bytes,
            int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }
}
