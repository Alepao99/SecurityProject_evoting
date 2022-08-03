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

public class SocketClient {

    private static void printUsage() {
        System.out.println("Usage:\n\tjava client.SocketClient [address] [port]");
    }

    private static void protocol(SSLSocket sslsocket) {
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
            protocol(sslsocket);

            //protocol(args[0], Integer.parseInt(args[1]));
        } catch (IOException ex) {
            Logger.getLogger(SocketClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
