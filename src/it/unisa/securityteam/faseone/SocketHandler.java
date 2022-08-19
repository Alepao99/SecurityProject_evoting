/*
 * SocketHandler.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 * 
 * A Thread to deal with socket messages.
 */
package it.unisa.securityteam.faseone;

import it.unisa.securityteam.utility.Utils;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;

public class SocketHandler extends Thread {

    private final int size = 32;

    private SSLSocket sslsocket = null;
    private String key = null;
    private HashMap<String, String> mapDatabaseUA;
    private HashMap<String, String> mapDatabaseId_Pkv;
    private String IdVoter = new String();

    /**
     * Constructor - initialize variables
     *
     * @param s - an ssl socket created by SocketListener
     */
    public SocketHandler(SSLSocket sslsocket, HashMap<String, String> mapDatabaseUA, HashMap<String, String> mapDatabaseId_Pkv) {
        this.sslsocket = sslsocket;
        this.mapDatabaseUA = mapDatabaseUA;
        this.mapDatabaseId_Pkv = mapDatabaseId_Pkv;
        try {
            start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
    pw serve per mandare
    br serve per ricevere
     */
    @Override
    public void run() {
        OutputStream out = null;
        InputStream in = null;
        ObjectOutputStream objectOut;
        ObjectInputStream inputStream;
        try {
            out = sslsocket.getOutputStream();
            in = sslsocket.getInputStream();

            objectOut = new ObjectOutputStream(out);
            inputStream = new ObjectInputStream(in);

            String fiscalCode = "";
            String userName = "";

            objectOut.writeObject("Insert Fiscal Code:");
            fiscalCode = (String) inputStream.readObject();

            objectOut.writeObject("Insert UserName:");
            userName = (String) inputStream.readObject();

            if (checkExisting(fiscalCode, userName)) {
                objectOut.writeBoolean(true);
                int repetition = 3;
                while (repetition > 0) {
                    objectOut.writeObject("\nPlease insert password for voting ");
                    String psw = (String) inputStream.readObject();

                    if (checkID(userName, psw)) {
                        objectOut.writeBoolean(true);
                        objectOut.writeObject("You have access!");
                        protocolElGamalClient(inputStream);
                        // protocolUpdateDataAuth();
                        break;
                    }
                    objectOut.writeBoolean(false);
                    repetition--;
                    if (repetition == 0) {
                        objectOut.writeObject("Attempts exhausted, Contact Assistance for Unlock");

                    } else {
                        objectOut.writeObject("Password error, You still have " + repetition + " attempts");
                    }

                }
            } else {
                objectOut.writeObject("User not present in database");
            }
        } catch (Exception ex) {
            Logger.getLogger(SocketHandler.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
                in.close();
                sslsocket.close();
                System.out.println("Session " + sslsocket + " close");
            } catch (IOException ex) {
                Logger.getLogger(SocketClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private boolean checkExisting(String fiscalCode, String userName) throws Exception {
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
        if (mapDatabaseUA.containsKey(Utils.toHex(encoded))) {
            this.key = Utils.toHex(encoded);
            return true;
        } else {
            return false;
        }
    }

    private boolean checkID(String userName, String psw) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();
        //String name = Utils.toHex(tempName); //sha256 Text

        hash.update(Utils.toByteArray(psw));
        byte[] tempPsw = hash.digest();
        //String psw = Utils.toHex(tempPsw);

        byte encoded[] = new byte[size];
        //System.out.println("message: " + toHex(tempName));

        for (int i = 0; i < size; i++) {
            encoded[i] = (byte) (tempName[i] ^ tempPsw[i]);
        }
        
        IdVoter = mapDatabaseUA.get(key);
        
        if (IdVoter.compareToIgnoreCase(Utils.toHex(encoded)) == 0) {
            return true;
        }
        IdVoter = "";
        return false;
    }

    private void protocolElGamalClient(ObjectInputStream inputStream) {
        try {
            BigInteger p = (BigInteger) inputStream.readObject();
            BigInteger q = (BigInteger) inputStream.readObject();
            BigInteger g = (BigInteger) inputStream.readObject();
            BigInteger h = (BigInteger) inputStream.readObject();
            String pkv = new String(p + " " + q + " " + g + " " + h);
            mapDatabaseId_Pkv.put(IdVoter, pkv);
        } catch (IOException ex) {
            Logger.getLogger(SocketHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(SocketHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        updateMapAuthFinish();

    }

    private void updateMapAuthFinish() {
        try ( BufferedWriter out = new BufferedWriter(new FileWriter("databaseId_Pkv.txt"))) {
            for (Map.Entry<String, String> x : mapDatabaseId_Pkv.entrySet()) {
                out.write(
                        x.getKey() + " "
                        + x.getValue() + "\n"
                );
            }
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(PreliminarySetting.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
    }

}
