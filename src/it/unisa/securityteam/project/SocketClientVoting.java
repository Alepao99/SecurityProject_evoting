/*
 * SocketClientVoting.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 * 
 * This class is the client which can send ssl socket to SocketListener. 
 * With both main() function and sendSocket() function, it can send a socket either from console
 * or inside programs. The return or output from the functions are the response from the socket.
 */
package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.*;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
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

    private static void readElGamal(String filename) {
        try ( ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(new FileInputStream(filename)))) {
            byte[] output = (byte[]) in.readObject();
            ByteArrayInputStream bis = new ByteArrayInputStream(output);
            ObjectInput inT = null;
            inT = new ObjectInputStream(bis);
            SK = (ElGamalSK) inT.readObject();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * main - send a socket from system command
     *
     * @param args[0] target address
     * @param args[1] target port
     * @param args[2] message
     *
     * @print received responses
     */
    private final static String filename = "ClientElGamal";
    private static ElGamalSK SK;
    private static final SecureRandom sc = new SecureRandom();

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
            readElGamal(filename);
            protocolCreateMsg(sslsocket);

            //protocol(args[0], Integer.parseInt(args[1]));
        } catch (IOException ex) {
            Logger.getLogger(SocketClientVoting.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:\n\tjava client.SocketClient [address] [port]");
    }

    private static void protocolCreateMsg(SSLSocket sslsocket) {
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
