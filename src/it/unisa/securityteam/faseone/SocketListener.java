/*
 * SocketListener.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 *
 * This class is a listener socket listener. Every ssl socket
 * will be assigned to a new thread called SocketHandler.
 */
package it.unisa.securityteam.faseone;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SocketListener {

    /**
     * main - listen a specific port. When receiving socket, start a new thread
     * to process data so that the program can process multiple socket at the
     * same time
     *
     */
    private static final String databaseUA = "databaseUA.txt";
    private static final String databaseId_Pkv = "databaseId_Pkv.txt";
    private static HashMap<String, String> mapDatabaseUA;
    private static HashMap<String, String> mapDatabaseId_Pkv;
    private static boolean stateRunning;

    private static HashMap<String, String> readFile(String filename) {
        //System.out.println("-----FILE-----");
        HashMap<String, String> map = new HashMap<>();
        try ( Scanner sc = new Scanner(new BufferedReader(new FileReader(filename)))) {
            sc.useLocale(Locale.US);
            sc.useDelimiter("\\s");
            while (sc.hasNext()) {
                map.put(sc.next(), sc.next());
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SocketHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return map;
    }

    private static void startTime(int timeStopVoting) throws InterruptedException {
        if (timeStopVoting < 0) {
            return;
        }
        stateRunning = true;

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeStopVoting);
                    stateRunning = false;
                } catch (InterruptedException ex) {
                    Logger.getLogger(SocketListener.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        t.start();
    }

    private static boolean isStateRunning() {
        return stateRunning;
    }

    public static void main(String[] args) throws InterruptedException {

        if (System.getProperty(
                "javax.net.ssl.keyStore") == null || System.getProperty("javax.net.ssl.keyStorePassword") == null) {
            // set keystore store location
            System.setProperty("javax.net.ssl.keyStore", "keystoreServerAuth");
            System.setProperty("javax.net.ssl.keyStorePassword", "serverAuthpwd");
        }
        // create socket
        SSLServerSocket sslserversocket = null;
        SSLSocket sslsocket = null;
        // create a listener on port 9999

        try {
            SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(4000);

            startTime(Integer.parseInt(args[0]));
            System.out.println("Start Server Auth");
            mapDatabaseUA = readFile(databaseUA);
            mapDatabaseId_Pkv = readFile(databaseId_Pkv);
            
            while (isStateRunning()) {
//Metto anche il read finish perchè ci sarà ogni volta che un utente accede ci sarà
                //un aggiornamento su questa mappa
                // blocks the program when no socket floats in
                sslsocket = (SSLSocket) sslserversocket.accept();
                System.out.println("sslsocket:" + sslsocket);
                // assign a handler to process data
                new SocketHandler(sslsocket, mapDatabaseUA, mapDatabaseId_Pkv);
            }
            System.out.println("Tempo scaduto");
        } catch (Exception e) {
            try {
                sslsocket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }

}
