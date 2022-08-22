/*
 * SocketListenerVoting.java
 * Author: Williams Wang
 * Last Edit: 8/20/2020 by why
 *
 * This class is a listener socket listener. Every ssl socket
 * will be assigned to a new thread called SocketHandlerVoting.
 */
package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.DecryptInTheExponent;
import static it.unisa.securityteam.project.ElGamal.Homomorphism;
import static it.unisa.securityteam.project.ElGamal.Setup;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SocketListenerVoting {

    /**
     * main - listen a specific port. When receiving socket, start a new thread
     * to process data so that the program can process multiple socket at the
     * same time
     *
     */
    private static final String smartContracts = "smartContracts.txt";
    private static final String databaseId_Pkv = "databaseId_Pkv.txt";
    private static HashMap<String, String> mapSmartContracts;
    private static HashMap<String, String> mapDatabaseId_Pkv;
    private static boolean stateRunning;
    private static ElGamalSK SKUA;

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
        // create a listener on port 9999

        try {
            SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(4001);

            startTime(Integer.parseInt(args[0]));
            SKUA = Setup(64);
            System.out.println("Start Server Voting");

            while (isStateRunning()) {
                sslsocket = (SSLSocket) sslserversocket.accept();
                System.out.println("sslsocket:" + sslsocket);
                new SocketHandlerVoting(sslsocket, SKUA);
            }
            System.out.println("Time is over");
            protocolRecostruction();
        } catch (Exception e) {
            try {
                sslsocket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }

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
                    Logger.getLogger(SocketListenerVoting.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        t.start();
    }

    private static boolean isStateRunning() {
        return stateRunning;
    }

    private static LinkedList<ElGamalCT> listValue() {
        LinkedList<ElGamalCT> list = new LinkedList<>();
        for (Map.Entry<String, String> x : mapSmartContracts.entrySet()) {
            String ctmsg = x.getValue();
            list.add(recoveryCT(ctmsg));
        }
        return list;
    }

    private static BigInteger resultVoting(LinkedList<ElGamalCT> list) {
        ElGamalCT CTH = list.get(0);
        for (int i = 1; i < list.size(); i++) {
            CTH = Homomorphism(SKUA.getPK(), CTH, list.get(i));
        }
        return DecryptInTheExponent(CTH, SKUA);
    }

    private static void protocolRecostruction() {
        mapSmartContracts = Utils.readFile(smartContracts);

        LinkedList<ElGamalCT> list = listValue();

        Utils.writeResult("Result.txt", resultVoting(list));

    }

    private static ElGamalCT recoveryCT(String ctmsg) {
        String[] parts = ctmsg.split(",");
        return new ElGamalCT(new BigInteger(parts[0]), new BigInteger(parts[1]));
    }

}
