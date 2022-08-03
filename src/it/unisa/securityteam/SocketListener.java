/*
 * SocketListener.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 *
 * This class is a listener socket listener. Every ssl socket
 * will be assigned to a new thread called SocketHandler.
 */
package it.unisa.securityteam;

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
    private int timeStopVoting;
    private boolean stateRunning;

    private static String database = "database.txt";
    private static HashMap<String, String> map = new HashMap<>();


    public SocketListener(int timeStopVoting) {
        if (timeStopVoting > 0) {
            this.timeStopVoting = timeStopVoting;
        }
        this.stateRunning = true;
    }

    private static void readData() {
        //System.out.println("-----FILE-----");
        try ( Scanner sc = new Scanner(new BufferedReader(new FileReader(database)))) {
            sc.useLocale(Locale.US);
            sc.useDelimiter("\\s");
            while (sc.hasNext()) {
                map.put(sc.next(), sc.next());
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SocketHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void startTime() throws InterruptedException {
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

    public boolean isStateRunning() {
        return stateRunning;
    }

    public static void main(String[] args) throws InterruptedException {
        if (System.getProperty("javax.net.ssl.keyStore") == null || System.getProperty("javax.net.ssl.keyStorePassword") == null) {
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
            SocketListener sl = new SocketListener(Integer.parseInt(args[0]));
            sl.startTime();
            readData();
            while (sl.isStateRunning()) {
                // blocks the program when no socket floats in
                sslsocket = (SSLSocket) sslserversocket.accept();
                System.out.println("sslsocket:" + sslsocket);
                // assign a handler to process data
                new SocketHandler(sslsocket, map);

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
