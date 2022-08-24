package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;

public class SocketHandlerVoting extends Thread {

    private SSLSocket sslsocket = null;
    private ElGamalPK PKUA = null;

    private HashMap<String, String> mapSmartContracts;
    private HashMap<String, String> mapDatabaseId_Pkv;

    private final String smartContracts = "smartContracts.txt";
    private final String databaseId_Pkv = "databaseId_Pkv.txt";

    /**
     * Constructor - initialize variables
     *
     * @param sslsocket
     * @param SKUA
     */
    public SocketHandlerVoting(SSLSocket sslsocket, ElGamalPK PKUA) {
        this.sslsocket = sslsocket;
        this.PKUA = PKUA;
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

            ElGamalPK PKVoter = (ElGamalPK) inputStream.readObject();

            String IDVoter = (String) inputStream.readObject();

            if (checkPKVoter(PKVoter, IDVoter)) {
                objectOut.writeBoolean(true);
                objectOut.flush();
                if (Utils.alreadyVoting(smartContracts, PKVoter)) {
                    objectOut.writeBoolean(true);
                    objectOut.flush();
                    objectOut.writeObject("This user has already voted\n");
                    objectOut.flush();
                    objectOut.writeObject("Do you want to vote with a new vote?");
                    objectOut.flush();
                    String x = (String) inputStream.readObject();
                    if (choise(x)) {
                        objectOut.writeBoolean(true);
                        protocolVoting(objectOut, inputStream, PKVoter);
                    } else {
                        objectOut.writeBoolean(false);
                        objectOut.writeObject("Closure");
                        objectOut.flush();
                    }
                } else {
                    objectOut.writeBoolean(false);
                    objectOut.flush();
                    protocolVoting(objectOut, inputStream, PKVoter);
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

    private void protocolVoting(ObjectOutputStream objectOut, ObjectInputStream inputStream, ElGamalPK PKVoter) {
        try {
            objectOut.writeObject("The user can vote");
            objectOut.flush();

            objectOut.writeObject(PKUA);
            objectOut.flush();
            objectOut.writeObject("Choose your voting preference for the referendum:\nyes\t\twhite\t\t\tno");
            objectOut.flush();

            ElGamalCT CTMsg = (ElGamalCT) inputStream.readObject();
            SchnorrSig s = (SchnorrSig) inputStream.readObject();
            if (Verify(PKVoter, s, CTMsg.toString())) {
                objectOut.writeBoolean(true);
                objectOut.flush();

                protocolUpdateSmartContracts(PKVoter, CTMsg);
                objectOut.writeObject("Vote added");
                objectOut.flush();
            } else {
                objectOut.writeBoolean(false);
                objectOut.flush();

            }
        } catch (IOException ex) {
            Logger.getLogger(SocketHandlerVoting.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(SocketHandlerVoting.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Check if the voter's PK is legitimate
     *
     * @param PKVoter
     * @return Boolean
     */
    private boolean checkPKVoter(ElGamalPK PKVoter, String IDVoter) {
        mapDatabaseId_Pkv = Utils.readFile(databaseId_Pkv);
        return mapDatabaseId_Pkv.get(IDVoter).compareToIgnoreCase(Utils.createStringPKElGamal(PKVoter)) == 0;
    }

    /**
     * Smart contract map update
     *
     * @param PKVoter
     * @param CTMsg
     */
    private void protocolUpdateSmartContracts(ElGamalPK PKVoter, ElGamalCT CTMsg) {
        mapSmartContracts = Utils.readFile(smartContracts);
        mapSmartContracts.put(Utils.createStringPKElGamal(PKVoter), Utils.createStringCTElGamal(CTMsg));
        Utils.writeFile(smartContracts, mapSmartContracts);
    }

    /**
     *
     * @param x
     * @return Boolean
     */
    private boolean choise(String x) {
        return x.compareToIgnoreCase("yes") == 0;
    }

}
