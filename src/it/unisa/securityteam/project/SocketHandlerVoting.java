/*
 * SocketHandlerVoting.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 * 
 * A Thread to deal with socket messages.
 */
package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.Verify;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;

public class SocketHandlerVoting extends Thread {

    // private final int size = 32;
    private SSLSocket sslsocket = null;
    private ElGamalSK SKUA = null;
    // private String key = null;
    private HashMap<String, String> mapSmartContracts;
    private HashMap<String, String> mapDatabaseId_Pkv;
    // private String IdVoter = new String();
    private final String smartContracts = "smartContracts.txt";
    private final String databaseId_Pkv = "databaseId_Pkv.txt";

    /**
     * Constructor - initialize variables
     *
     * @param s - an ssl socket created by SocketListener
     */
    /* public SocketHandlerVoting(SSLSocket sslsocket, HashMap<String, String> mapDatabaseUA, HashMap<String, String> mapDatabaseId_Pkv) {
        this.sslsocket = sslsocket;
        this.mapDatabaseUA = mapDatabaseUA;
        this.mapDatabaseId_Pkv = mapDatabaseId_Pkv;
        try {
            start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
     */
    public SocketHandlerVoting(SSLSocket sslsocket, ElGamalSK SKUA) {
        this.sslsocket = sslsocket;
        this.SKUA = SKUA;
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

            ElGamalPK PKVoter = (ElGamalPK) inputStream.readObject();
            if (checkPKVoter(PKVoter)) {
                objectOut.writeBoolean(true);
                objectOut.flush();

                objectOut.writeObject("The user can vote");
                objectOut.flush();

                objectOut.writeObject(SKUA);
                objectOut.flush();
                objectOut.writeObject("Choise your preference:\n1: Yes\t0: white\t-1: No");
                objectOut.flush();
                //fiscalCode = (String) inputStream.readObject();

                ElGamalCT CTMsg = (ElGamalCT) inputStream.readObject();
                SchnorrSig s = (SchnorrSig) inputStream.readObject();
                if (Verify(s, PKVoter, CTMsg.toString())) {
                    objectOut.writeBoolean(true);
                    objectOut.flush();

                    protocolUpdateSmartContracts(PKVoter, CTMsg);
                    objectOut.writeObject("Vote added");
                    objectOut.flush();
                } else {
                    objectOut.writeBoolean(false);
                    objectOut.flush();

                }
            } else {
                objectOut.writeBoolean(false);
                objectOut.writeObject("The user can not vote");
                objectOut.flush();
            }

        } catch (Exception ex) {
            Logger.getLogger(SocketHandlerVoting.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
                in.close();
                sslsocket.close();
                System.out.println("Session " + sslsocket + " close");
            } catch (IOException ex) {
                Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }


    private boolean checkPKVoter(ElGamalPK PKVoter) {
        mapDatabaseId_Pkv = Utils.readFile(databaseId_Pkv);
        if (mapDatabaseId_Pkv.containsValue(Utils.createStringPKElGamal(PKVoter))) {
            return true;
        }
        return false;
    }

    private void protocolUpdateSmartContracts(ElGamalPK PKVoter, ElGamalCT CTMsg) {
        mapSmartContracts = Utils.readFile(smartContracts);
        mapSmartContracts.put(Utils.createStringPKElGamal(PKVoter), Utils.createStringCTElGamal(CTMsg));

        try ( BufferedWriter out = new BufferedWriter(new FileWriter(smartContracts))) {
            for (Map.Entry<String, String> x : mapSmartContracts.entrySet()) {
                out.write(
                        x.getKey() + " "
                        + x.getValue() + "\n"
                );

            }
        } catch (IOException ex) {
            Logger.getLogger(SocketListenerVoting.class
                    .getName()).log(Level.SEVERE, null, ex);
        }

    }

}
