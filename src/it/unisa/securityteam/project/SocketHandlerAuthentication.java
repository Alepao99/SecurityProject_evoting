package it.unisa.securityteam.project;

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

public class SocketHandlerAuthentication extends Thread {

    private final int size = 32;

    private SSLSocket sslsocket = null;
    private String key = null;
    private HashMap<String, String> mapDatabaseUA;
    private HashMap<String, String> mapDatabaseId_PKvoter;
    private String IdVoter = new String();

    /**
     * Constructor - initialize variables
     *
     * @param sslsocket
     * @param mapDatabaseUA
     * @param mapDatabaseId_PKvoter
     */
    public SocketHandlerAuthentication(SSLSocket sslsocket, HashMap<String, String> mapDatabaseUA, HashMap<String, String> mapDatabaseId_PKvoter) {
        this.sslsocket = sslsocket;
        this.mapDatabaseUA = mapDatabaseUA;
        this.mapDatabaseId_PKvoter = mapDatabaseId_PKvoter;
        try {
            start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

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

            objectOut.writeObject("Insert Fiscal Code:");
            objectOut.flush();

            String fiscalCode = (String) inputStream.readObject();

            objectOut.writeObject("Insert UserName:");
            objectOut.flush();

            String userName = (String) inputStream.readObject();

            if (!checkExisting(fiscalCode, userName)) {
                objectOut.writeBoolean(false);
                objectOut.flush();
                objectOut.writeObject("User not present in database");
                objectOut.flush();
            } else {
                objectOut.writeBoolean(true);
                objectOut.flush();

                int repetition = 3;
                while (repetition > 0) {
                    objectOut.writeObject("\nPlease insert password for voting ");
                    objectOut.flush();

                    String psw = (String) inputStream.readObject();

                    if (checkID(userName, psw)) {
                        objectOut.writeBoolean(true);
                        objectOut.flush();
                        objectOut.writeObject("You have access!");
                        objectOut.flush();

                        if (firstAccessClient()) {
                            objectOut.writeBoolean(true);
                            objectOut.flush();
                            protocolFirstAccess(inputStream);
                        } else {
                            objectOut.writeBoolean(false);
                            objectOut.flush();
                        }
                        break;
                    }
                    objectOut.writeBoolean(false);
                    repetition--;
                    if (repetition == 0) {
                        objectOut.writeObject("Attempts exhausted, Contact Assistance for Unlock");
                        objectOut.flush();
                    } else {
                        objectOut.writeObject("Password error, You still have " + repetition + " attempts");
                        objectOut.flush();
                    }

                }
            }
        } catch (Exception ex) {
            Logger.getLogger(SocketHandlerAuthentication.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
                in.close();
                sslsocket.close();
                System.out.println("Session " + sslsocket + " close");
            } catch (IOException ex) {
                Logger.getLogger(SocketClientAuthentication.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * Check the client input data. Check key map Authenticator exist.
     *
     * @param fiscalCode
     * @param userName
     * @return Boolean
     * @throws Exception *
     *
     */
    private boolean checkExisting(String fiscalCode, String userName) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();

        hash.update(Utils.toByteArray(fiscalCode));
        byte[] tempFC = hash.digest();

        byte encoded[] = new byte[size];

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

    /**
     *
     * Check the client input data. Check value-Id map Authenticator
     *
     * @param userName
     * @param psw
     * @return Boolean
     * @throws Exception
     */
    private boolean checkID(String userName, String psw) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        hash.update(Utils.toByteArray(userName));
        byte[] tempName = hash.digest();

        hash.update(Utils.toByteArray(psw));
        byte[] tempPsw = hash.digest();

        byte encoded[] = new byte[size];

        for (int i = 0; i < size; i++) {
            encoded[i] = (byte) (tempName[i] ^ tempPsw[i]);
        }

        IdVoter = mapDatabaseUA.get(key);

        if (IdVoter.compareToIgnoreCase(Utils.toHex(encoded)) == 0) {
            return true;
        }
        IdVoter = null;
        return false;
    }

    /**
     *
     * It takes the voter's PK and stores it in the Id_PK map
     *
     * @param inputStream
     */
    private void protocolFirstAccess(ObjectInputStream inputStream) {
        try {
            BigInteger p = (BigInteger) inputStream.readObject();
            BigInteger q = (BigInteger) inputStream.readObject();
            BigInteger g = (BigInteger) inputStream.readObject();
            BigInteger h = (BigInteger) inputStream.readObject();
            int securityparameter = (Integer) inputStream.readObject();
            mapDatabaseId_PKvoter.put(IdVoter, Utils.createStringPKElGamal(new ElGamalPK(p, q, g, h, securityparameter)));
        } catch (IOException ex) {
            Logger.getLogger(SocketHandlerAuthentication.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(SocketHandlerAuthentication.class.getName()).log(Level.SEVERE, null, ex);
        }
        updateMapAuthFinish();

    }

    /**
     * Update the logged in customer file. Stores the customer's ID and PK
     */
    private void updateMapAuthFinish() {
        try ( BufferedWriter out = new BufferedWriter(new FileWriter("databaseId_Pkv.txt"))) {
            for (Map.Entry<String, String> x : mapDatabaseId_PKvoter.entrySet()) {
                out.write(
                        x.getKey() + " "
                        + x.getValue() + "\n"
                );
            }
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(PreliminarySetting.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
    }

    /**
     * 
     * @return Boolean
     */
    private boolean firstAccessClient() {
        return mapDatabaseId_PKvoter.get(IdVoter).compareToIgnoreCase("null") == 0;
    }
}
