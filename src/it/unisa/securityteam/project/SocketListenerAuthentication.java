package it.unisa.securityteam.project;

import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SocketListenerAuthentication {

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
                    Logger.getLogger(SocketListenerAuthentication.class.getName()).log(Level.SEVERE, null, ex);
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
        // create a listener on port 4000

        try {
            SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(4000);

            startTime(Integer.parseInt(args[0]));
            System.out.println("Start Server Authentication");
            mapDatabaseUA = Utils.readFile(databaseUA);
            mapDatabaseId_Pkv = Utils.readFile(databaseId_Pkv);

            while (isStateRunning()) {

                sslsocket = (SSLSocket) sslserversocket.accept();
                System.out.println("sslsocket:" + sslsocket);
                // assign a handler to process data
                new SocketHandlerAuthentication(sslsocket, mapDatabaseUA, mapDatabaseId_Pkv);
            }
            System.out.println("Time is over");
        } catch (Exception e) {
            try {
                sslsocket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }
}
