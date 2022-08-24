package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.*;
import java.net.Socket;
import java.io.*;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class DealerSKAU {

    private static final int num_authority = 2;

    /**
     * Protocol execution Dealer
     * @param sSock
     * @param SKP
     * @param PKAU
     * @throws Exception 
     */
    static void Protocol(Socket sSock, ElGamalSK SKP, ElGamalPK PKAU) throws Exception {

        OutputStream out = sSock.getOutputStream();

        try {

            ObjectOutputStream objectOut;

            objectOut = new ObjectOutputStream(out);

            objectOut.writeObject(SKP);
            objectOut.flush();
            objectOut.writeObject(PKAU);
            objectOut.flush();

            out.close();
            sSock.close(); // close connection
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception {

        if (System.getProperty(
                "javax.net.ssl.keyStore") == null || System.getProperty("javax.net.ssl.keyStorePassword") == null) {
            // set keystore store location
            System.setProperty("javax.net.ssl.keyStore", "keystoreServerDealer");
            System.setProperty("javax.net.ssl.keyStorePassword", "serverDealer");
        }
        // create socket
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        SSLServerSocket sSock;
        SSLSocket[] sslSock = new SSLSocket[num_authority];
        sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // bind to port 4000

        ElGamalSK Params = SetupParameters(64); // in real implementation set the security parameter to at least 2048 bits
        //there is some non-trusted entity that generates the parameters

        // we now suppose there are 2 authorities
        ElGamalSK[] SK = new ElGamalSK[num_authority];
        for (int i = 0; i < 2; i++) {
            SK[i] = Setup(Params);
        }

        ElGamalPK[] PartialPK = new ElGamalPK[num_authority];
        for (int i = 0; i < num_authority; i++) {
            PartialPK[i] = SK[i].getPK();
        }

        ElGamalPK PKAU = AggregatePartialPublicKeys(PartialPK);
        for (int i = 0; i < num_authority; i++) {
            System.out.println("Waiting for connections...");
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("Connection to Authority Server\n");
            Protocol(sslSock[i], SK[i], PKAU);
            System.out.println("Partial secret key sent successfully\n");
        }

    }
}
