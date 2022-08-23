package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SocketClientVoting {

    private final static String fileClientSK = "ClientElGamal";
    private static ElGamalSK SK;
    private static final SecureRandom sc = new SecureRandom();

    /**
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            printUsage();
            return;
        }
        if (System.getProperty("javax.net.ssl.trustStore") == null || System.getProperty("javax.net.ssl.trustStorePassword") == null) {
            System.setProperty("javax.net.ssl.trustStore", "truststoServerVoting");
            System.setProperty("javax.net.ssl.trustStorePassword", "serverVoting");
        }
        try {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(args[0], Integer.parseInt(args[1]));
            sslsocket.startHandshake();
            System.out.println("sslsocket=" + sslsocket);
            SK = Utils.readSKByte(fileClientSK, SK);
            protocolVoting(sslsocket);

            //protocol(args[0], Integer.parseInt(args[1]));
        } catch (IOException ex) {
            Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:\n\tjava client.SocketClient [address] [port]");
    }

    /**
     *
     * Client Voting Execution Protocol
     *
     * @param sslsocket
     */
    private static void protocolVoting(SSLSocket sslsocket) {
        OutputStream out = null;
        InputStream in = null;
        ObjectOutputStream objectOut;
        ObjectInputStream inputStream;
        try {
            out = sslsocket.getOutputStream();
            in = sslsocket.getInputStream();

            objectOut = new ObjectOutputStream(out);
            inputStream = new ObjectInputStream(in);
            Scanner scanner = new Scanner(System.in);

            objectOut.writeObject(SK.getPK());
            objectOut.flush();

            if (inputStream.readBoolean()) {
                System.out.println((String) inputStream.readObject());

                ElGamalSK SKUA = (ElGamalSK) inputStream.readObject();
                System.out.println((String) inputStream.readObject());

                BigInteger x = scanner.nextBigInteger();
                ElGamalCT CTMsg = EncryptInTheExponent(SKUA.getPK(), x);
                objectOut.writeObject(CTMsg);
                objectOut.flush();

                SchnorrSig s = Sign(SK, CTMsg.toString());
                System.out.println(CTMsg.toString());
                objectOut.writeObject(s);
                objectOut.flush();

                if (inputStream.readBoolean()) {
                    System.out.println("Request to add vote");
                    System.out.println((String) inputStream.readObject());
                } else {
                    System.out.println("Request to add vote denied");
                }
            } else {
                System.out.println((String) inputStream.readObject());
            }

        } catch (Exception ex) {
            Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
                in.close();
                sslsocket.close();
                System.out.println("Session close");
            } catch (IOException ex) {
                Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

    }

}
