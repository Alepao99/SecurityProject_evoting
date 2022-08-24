package it.unisa.securityteam.project;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SocketListenerVoting {

    private static boolean stateRunning;
    private static ElGamalSK SKAUP;
    private static ElGamalPK PKAU;

    /**
     *
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
                    Logger.getLogger(SocketListenerVoting.class.getName()).log(Level.SEVERE, null, ex);
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
            System.setProperty("javax.net.ssl.keyStore", "keystoreServerVoting");
            System.setProperty("javax.net.ssl.keyStorePassword", "serverVoting");
        }
        // create socket
        SSLServerSocket sslserversocket = null;
        SSLSocket sslsocket = null;
        // create a listener on port 4001

        try {
            SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(4001);

            startTime(Integer.parseInt(args[0]));
            SKAUP = Utils.readSKByte("SecretPartialVoting", SKAUP);
            PKAU = Utils.readPKByte("PKAUfromVoting", PKAU);
            System.out.println("\t\tStart Server Voting");

            while (isStateRunning()) {
                sslsocket = (SSLSocket) sslserversocket.accept();
                System.out.println("sslsocket:" + sslsocket);
                // assign a handler to process data
                new SocketHandlerVoting(sslsocket, PKAU);
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
