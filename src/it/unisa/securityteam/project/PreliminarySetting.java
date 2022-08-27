/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package it.unisa.securityteam.project;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author apaolillo
 */
public class PreliminarySetting {

    private static final int size = 32;
    private static final String dirName = "/home/apaolillo/NetBeansProjects/ProjectCyberSecurity/src";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String databaseUA = "databaseUA.txt";
        String databaseId_Pkv = "databaseId_Pkv.txt";

        HashMap<String, String> mapAuthStart = new HashMap<>(); //chiave = name^CF; value = ID = name^pass
        HashMap<String, String> mapAuthFinish = new HashMap<>(); //chiave = ID; value = Pkv

        List<User> list = new ArrayList<>();

        list.add(new User("u1@gmail.com", "fc1", "psw1"));
        list.add(new User("u2@gmail.com", "fc2", "psw2"));
        list.add(new User("u3@gmail.com", "fc3", "psw3"));
        list.add(new User("u4@gmail.com", "fc4", "psw4"));
        for (User x : list) {
            mapAuthStart.put(getKey(x.getUserName(), x.getFiscalCode()), getID(x.getUserName(), x.getPsw()));
            mapAuthFinish.put(getID(x.getUserName(), x.getPsw()), "null");
        }
        Utils.writeFile(databaseUA, mapAuthStart);
        Utils.writeFile(databaseId_Pkv, mapAuthFinish);
        deleteFileContents("smartContracts.txt");
        deleteFileContents("ClientElGamalSK");
        deleteFileContents("ClientElGamalID");
        deleteFileContents("PKAUfromAuth");
        deleteFileContents("PKAUfromVoting");
        deleteFileContents("SecretPartialAuth");
        deleteFileContents("SecretPartialVoting");

    }

    private static String getKey(String userName, String fiscalCode) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();
        //String name = Utils.toHex(tempName); //sha256 Text

        hash.update(Utils.toByteArray(fiscalCode));
        byte[] tempFC = hash.digest();
        //String fc = Utils.toHex(tempFC);

        byte encoded[] = new byte[size];
        //System.out.println("message: " + toHex(tempName));

        for (int i = 0; i < size; i++) {
            encoded[i] = (byte) (tempName[i] ^ tempFC[i]);
        }
        return Utils.toHex(encoded);
    }

    private static String getID(String userName, String psw) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();
        //String name = Utils.toHex(tempName); //sha256 Text

        hash.update(Utils.toByteArray(psw));
        byte[] tempPsw = hash.digest();
        //String fc = Utils.toHex(tempPsw);

        byte encoded[] = new byte[size];
        //System.out.println("message: " + toHex(tempName));

        for (int i = 0; i < size; i++) {
            encoded[i] = (byte) (tempName[i] ^ tempPsw[i]);
        }
        return Utils.toHex(encoded);
    }

    private static void deleteFileContents(String filename) {
        PrintWriter writer = null;
        try {
            File file = new File(dirName, filename);
            writer = new PrintWriter(file);
            writer.print("");
            // other operations
            writer.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PreliminarySetting.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            writer.close();
        }

    }

}
