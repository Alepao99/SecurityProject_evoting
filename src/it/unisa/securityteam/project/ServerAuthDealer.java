/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package it.unisa.securityteam.project;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 *
 * @author apaolillo
 */
public class ServerAuthDealer {

    public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            printUsage();
            return;
        }
        if (System.getProperty("javax.net.ssl.trustStore") == null || System.getProperty("javax.net.ssl.trustStorePassword") == null) {
            System.setProperty("javax.net.ssl.trustStore", "truststoServerDealer");
            System.setProperty("javax.net.ssl.trustStorePassword", "serverDealer");
        }
        try {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(args[0], Integer.parseInt(args[1]));
            sslsocket.startHandshake();
            System.out.println("sslsocket=" + sslsocket);
            protocolSKPartialPKAU(sslsocket);

            //protocol(args[0], Integer.parseInt(args[1]));
        } catch (IOException ex) {
            Logger.getLogger(ServerAuthDealer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void printUsage() {
        System.out.println("Usage:\n\tjava client.SocketClient [address] [port]");
    }

    private static void protocolSKPartialPKAU(SSLSocket sslsocket) throws IOException {
        InputStream in = sslsocket.getInputStream();

        try {
            ObjectInputStream inputStream;

            inputStream = new ObjectInputStream(in);
            ElGamalSK SKP = (ElGamalSK) inputStream.readObject();
            ElGamalPK PKAU = (ElGamalPK) inputStream.readObject();
            Utils.writeSKByte(SKP, "SecretPartialAuth");
            Utils.writePKAUByte(PKAU, "PKAUfromAuth");
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
                sslsocket.close();
            } catch (IOException ex) {
                Logger.getLogger(ServerAuthDealer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
