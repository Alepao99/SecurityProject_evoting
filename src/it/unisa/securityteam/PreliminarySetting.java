/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package it.unisa.securityteam;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author apaolillo
 */
public class PreliminarySetting {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String database = "database.txt";

        HashMap<String, String> map = new HashMap<>();

        List<User> list = new ArrayList<>();

        list.add(new User("a.paolillo26@studenti.unisa.it", "PLLLSN99C20A717X", "password1"));
        list.add(new User("t.landi3@studenti.unisa.it", "PLLLSN99C20A717X", "password2"));
        list.add(new User("f.santorelli8@studenti.unisa.it", "PLLLSN99C20A717X", "password3"));
        list.add(new User("m.savarese18@studenti.unisa.it", "PLLLSN99C20A717X", "password4"));
        list.add(new User("prova", "prova", "psw"));
        for (User x : list) {
            map.put(getKey(x.getUserName(), x.getFiscalCode()), getID(x.getUserName(), x.getPsw()));
        }
        writeFile(database, map);

    }

    private static void writeFile(String filename, Map<String, String> map) {
        try ( BufferedWriter out = new BufferedWriter(new FileWriter(filename))) {
            for (Map.Entry<String, String> x : map.entrySet()) {
                out.write(
                        x.getKey() + " "
                        + x.getValue() + "\n"
                );
            }

        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(PreliminarySetting.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
    }

    private static String getKey(String userName, String fiscalCode) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();
        //String name = Utils.toHex(tempName); //sha256 Text

        hash.update(Utils.toByteArray(fiscalCode));
        byte[] tempFC = hash.digest();
        //String fc = Utils.toHex(tempFC);

        byte encoded[] = new byte[tempName.length];
        //System.out.println("message: " + toHex(tempName));

        for (int i = 0; i < tempName.length; i++) {
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

        byte encoded[] = new byte[tempName.length];
        //System.out.println("message: " + toHex(tempName));

        for (int i = 0; i < tempName.length; i++) {
            encoded[i] = (byte) (tempName[i] ^ tempPsw[i]);
        }
        return Utils.toHex(encoded);
    }

}
