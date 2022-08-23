package it.unisa.securityteam.project;

import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SocketListenerAuthentication {

    private static final String databaseUA = "databaseUA.txt";
    private static final String databaseId_PKVoter = "databaseId_Pkv.txt";
    private static HashMap<String, String> mapDatabaseUA;
    private static HashMap<String, String> mapDatabaseId_PKVoter;
    private static boolean stateRunning;

    /**
     * This function launches a thread that, based on the timeStopVooting value,
     * stops the server authentication request.
     *
     * @param timeStopVoting
     * @throws InterruptedException
     */
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

    /**
     *
     * @return Boolean
     */
    private static boolean isStateRunning() {
        return stateRunning;
    }

    /**
     *
     * Main - listen a specific port. When receiving socket, start a new thread
     * to process data so that the program can process multiple socket at the
     * same time
     *
     * @param args
     * @throws InterruptedException
     */
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
            mapDatabaseId_PKVoter = Utils.readFile(databaseId_PKVoter);

            while (isStateRunning()) {

                sslsocket = (SSLSocket) sslserversocket.accept();
                System.out.println("sslsocket:" + sslsocket);
                // assign a handler to process data
                new SocketHandlerAuthentication(sslsocket, mapDatabaseUA, mapDatabaseId_PKVoter);
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
