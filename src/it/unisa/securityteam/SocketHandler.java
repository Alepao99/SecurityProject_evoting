/*
 * SocketHandler.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 * 
 * A Thread to deal with socket messages.
 */
package it.unisa.securityteam;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;

public class SocketHandler extends Thread {

    private SSLSocket sslsocket = null;
    private static String key = new String();
    private HashMap<String, String> map;

    /**
     * Constructor - initialize variables
     *
     * @param s - an ssl socket created by SocketListener
     */
    public SocketHandler(SSLSocket sslsocket, HashMap<String, String> map) {
        this.sslsocket = sslsocket;
        this.map = map;
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

                    if (checkUser(userName, psw)) {
                        objectOut.writeBoolean(true);
                        objectOut.writeObject("You have access!");
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

    private boolean checkUser(String userName, String psw) throws Exception {
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
