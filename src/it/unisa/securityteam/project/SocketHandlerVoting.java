/*
 * SocketHandlerVoting.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 * 
 * A Thread to deal with socket messages.
 */
package it.unisa.securityteam.project;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;

public class SocketHandlerVoting extends Thread {

    // private final int size = 32;
    private SSLSocket sslsocket = null;
    // private String key = null;
    // private HashMap<String, String> mapDatabaseUA;
    // private HashMap<String, String> mapDatabaseId_Pkv;
    // private String IdVoter = new String();

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
    public SocketHandlerVoting(SSLSocket sslsocket) {
        this.sslsocket = sslsocket;
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

}
