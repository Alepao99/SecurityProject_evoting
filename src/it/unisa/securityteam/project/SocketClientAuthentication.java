package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.Setup;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SocketClientAuthentication {

    private static final String fileClientSK = "ClientElGamal";

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
            Logger.getLogger(SocketClientAuthentication.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:\n\tjava client.SocketClient [address] [port]");
    }

    /**
     * Communication protocol with the authentication server
     * @param sslsocket 
     */
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
            objectOut.flush();

            System.out.println((String) inputStream.readObject());
            String userName = scanner.next();
            objectOut.writeObject(userName);
            objectOut.flush();

            if (inputStream.readBoolean()) {
                int repetition = 3;
                while (repetition > 0) {
                    System.out.println((String) inputStream.readObject());
                    String psw = scanner.next();
                    objectOut.writeObject(psw);
                    objectOut.flush();

                    if (inputStream.readBoolean()) {
                        System.out.println((String) inputStream.readObject());
                        //if (firstAccess())
                        if (inputStream.readBoolean()) {
                            protocolFirstAccess(objectOut);
                        }
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
            Logger.getLogger(SocketClientAuthentication.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                out.close();
                in.close();
                sslsocket.close();
                System.out.println("Session close");
            } catch (IOException ex) {
                Logger.getLogger(SocketClientAuthentication.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

    }

    /**
     * 
     * @param objectOut 
     */
    private static void protocolFirstAccess(ObjectOutputStream objectOut) {
        ElGamalSK SK = Setup(64); //questioni di tempo a 64 altrienti 2048 
        try {
            objectOut.writeObject(SK.getPK().getP());
            objectOut.flush();

            objectOut.writeObject(SK.getPK().getQ());
            objectOut.flush();

            objectOut.writeObject(SK.getPK().getG());
            objectOut.flush();

            objectOut.writeObject(SK.getPK().getH());
            objectOut.flush();

            objectOut.writeObject(SK.getPK().getSecurityparameter());
            objectOut.flush();
        } catch (IOException ex) {
            Logger.getLogger(SocketClientAuthentication.class.getName()).log(Level.SEVERE, null, ex);
        }

        Utils.writeSKByte(SK, fileClientSK);
    }

}
