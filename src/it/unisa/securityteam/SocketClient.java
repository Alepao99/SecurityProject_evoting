/*
 * SocketClient.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 * 
 * This class is the client which can send ssl socket to SocketListener. 
 * With both main() function and sendSocket() function, it can send a socket either from console
 * or inside programs. The return or output from the functions are the response from the socket.
 */
package it.unisa.securityteam;

import static it.unisa.securityteam.ElGamal.Setup;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SocketClient {

    /**
     * main - send a socket from system command
     *
     * @param args[0] target address
     * @param args[1] target port
     * @param args[2] message
     *
     * @print received responses
     */
    public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            printUsage();
            return;
        }
        if (System.getProperty("javax.net.ssl.trustStore") == null || System.getProperty("javax.net.ssl.trustStorePassword") == null) {
            System.setProperty("javax.net.ssl.trustStore", "truststoServerAuth");
            System.setProperty("javax.net.ssl.trustStorePassword", "serverAuthpwd");
        }
        try {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(args[0], Integer.parseInt(args[1]));
            sslsocket.startHandshake();
            System.out.println("sslsocket=" + sslsocket);
            protocolAuth(sslsocket);

            //protocol(args[0], Integer.parseInt(args[1]));
        } catch (IOException ex) {
            Logger.getLogger(SocketClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:\n\tjava client.SocketClient [address] [port]");
    }

    private static void protocolAuth(SSLSocket sslsocket) {
        OutputStream out = null;
        InputStream in = null;
        ObjectOutputStream objectOut;
        ObjectInputStream inputStream;
        try {
            out = sslsocket.getOutputStream();
            in = sslsocket.getInputStream();
            //protocol(sslsocket);

            objectOut = new ObjectOutputStream(out);
            inputStream = new ObjectInputStream(in);
            Scanner scanner = new Scanner(System.in);

            System.out.println((String) inputStream.readObject());
            String fiscalCode = scanner.next();
            objectOut.writeObject(fiscalCode);

            System.out.println((String) inputStream.readObject());
            String userName = scanner.next();
            objectOut.writeObject(userName);

            if (inputStream.readBoolean()) {
                int repetition = 3;
                while (repetition > 0) {
                    System.out.println((String) inputStream.readObject());
                    String psw = scanner.next();
                    objectOut.writeObject(psw);
                    if (inputStream.readBoolean()) {
                        System.out.println((String) inputStream.readObject());
                        protocolElGamalClient(objectOut, sslsocket);
                        break;
                    }
                    repetition--;
                    if (repetition == 0) {
                        System.err.println((String) inputStream.readObject());

                    } else {
                        System.err.println((String) inputStream.readObject());
                    }

                }
            } else {
                System.err.println((String) inputStream.readObject());
            }
        } catch (Exception ex) {
            Logger.getLogger(SocketClient.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
                in.close();
                sslsocket.close();
                System.out.println("Session close");
            } catch (IOException ex) {
                Logger.getLogger(SocketClient.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

    }

    private static void protocolElGamalClient(ObjectOutputStream objectOut, SSLSocket sslsocket) {
        ElGamalSK SK = Setup(64); //questioni di tempo a 64 altrienti 2048 
        try {
            objectOut.writeObject(SK.PK.p);
            objectOut.writeObject(SK.PK.q);
            objectOut.writeObject(SK.PK.g);
            objectOut.writeObject(SK.PK.h);
        } catch (IOException ex) {
            Logger.getLogger(SocketClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        writeFile(SK, "ClientElgamal" + sslsocket.getLocalPort() + ".txt");

    }

    private static void writeFile(ElGamalSK SK, String filename) {
        try ( BufferedWriter out = new BufferedWriter(new FileWriter(filename))) {
            out.write(
                    SK.PK.p + " "
                    + SK.PK.q + " "
                    + SK.PK.g + " "
                    + SK.PK.h + " "
                    + SK.s + "\n"
            );
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(PreliminarySetting.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
    }

}
