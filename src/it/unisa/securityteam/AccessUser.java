/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package it.unisa.securityteam;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Scanner;

/**
 *https://github.com/Alepao99/SecurityProject.git
 * @author apaolillo
 */
public class AccessUser {

    private static String database = "database.txt";
    private static HashMap<String, String> map = new HashMap<>();
    private static String key = new String();

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        //inserisci fiscal code
        //se non c'è nel database allora non ha mai ricevuto l'id valido
        //se è presente il codice fiscale allora deve effettuare l'accesso inserendo le credenziali nome e psw
        //se il controllo è valido allora l'utente esiste nel database e può effettuare la votazione.
        readData();

        System.out.println("Insert Fiscal Code:");
        Scanner scanner = new Scanner(System.in);
        String fiscalCode = scanner.next();
        System.out.println("Insert UserName:");
        String userName = scanner.next();

        if (checkExisting(fiscalCode, userName)) {
            System.out.print("\nUser present in database ");
            int repetition = 3;
            while (repetition > 0) {
                System.out.println("please insert password for voting:");
                String psw = scanner.next();
                if (checkUser(userName, psw)) {
                    System.out.println("You have access!");
                    break;
                } else {
                    repetition--;
                    if (repetition == 0) {
                        System.err.println("Attempts exhausted, Contact Assistance for Unlock");
                    } else {
                        System.out.println("Password error, You still have " + repetition + " attempts");
                    }
                }
            }
        } else {
            System.err.println("User not present in database");
        }
    }

    private static void readData() throws FileNotFoundException {
        System.out.println("-----FILE-----");
        try ( Scanner sc = new Scanner(new BufferedReader(new FileReader(database)))) {
            sc.useLocale(Locale.US);
            sc.useDelimiter("\\s");
            while (sc.hasNext()) {
                map.put(sc.next(), sc.next());
            }
        }
    }

    /*
    private static void stampaMap(Map<String, String> map) {
        for (Map.Entry<String, String> entry : map.entrySet()) {
            System.out.println(entry.getKey() + " " + entry.getValue());
        }
    }
     */
    //un altro modo per vedere se è corretto è questo
    /*
            byte decoded[] = new byte[message.length];

        for (int i = 0; i < message.length; i++) {
            decoded[i] = (byte) (encoded[i] ^ key[i]);
        }

        System.out.println("decoded: " + toHex(decoded) + " " + Arrays.equals(message, decoded));

    leggiamo ogni chiave del database ed effettuamo per ogni chiave lo xor con il fiscalCode e vediamo se esce 
    lo userName se è cosi allora abbiamo effettuato al codifica
     */
    private static boolean checkExisting(String fiscalCode, String userName) throws Exception {
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
        if (map.containsKey(Utils.toHex(encoded))) {
            key = Utils.toHex(encoded);
            return true;
        } else {
            return false;
        }
    }

    private static boolean checkUser(String userName, String psw) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();
        //String name = Utils.toHex(tempName); //sha256 Text

        hash.update(Utils.toByteArray(psw));
        byte[] tempPsw = hash.digest();
        //String psw = Utils.toHex(tempPsw);

        byte encoded[] = new byte[tempName.length];
        //System.out.println("message: " + toHex(tempName));

        for (int i = 0; i < tempName.length; i++) {
            encoded[i] = (byte) (tempName[i] ^ tempPsw[i]);
        }
        String value = map.get(key);
        return value.compareToIgnoreCase(Utils.toHex(encoded)) == 0;
    }

}
