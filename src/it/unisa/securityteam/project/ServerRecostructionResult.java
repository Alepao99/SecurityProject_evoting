/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package it.unisa.securityteam.project;

import static it.unisa.securityteam.project.ElGamal.AggregatePartialPublicKeys;
import static it.unisa.securityteam.project.ElGamal.DecryptInTheExponent;
import static it.unisa.securityteam.project.ElGamal.Homomorphism;
import static it.unisa.securityteam.project.ElGamal.PartialDecrypt;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 *
 * @author apaolillo
 */
public class ServerRecostructionResult {

    private static final int num_authority = 2;
    private static final String smartContracts = "smartContracts.txt";
    private static HashMap<String, String> mapSmartContracts;
    private static ElGamalPK PKAU;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        if (System.getProperty(
                "javax.net.ssl.keyStore") == null || System.getProperty("javax.net.ssl.keyStorePassword") == null) {
            // set keystore store location
            System.setProperty("javax.net.ssl.keyStore", "keystoreServerRec");
            System.setProperty("javax.net.ssl.keyStorePassword", "serverRec");
        }
        // create socket
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault(); //
        SSLServerSocket sSock;
        SSLSocket[] sslSock = new SSLSocket[num_authority];
        sSock = (SSLServerSocket) sockfact.createServerSocket(4000); // bind to port 4000

        ElGamalSK[] SKAU = new ElGamalSK[num_authority];
        ElGamalPK[] PartialPK = new ElGamalPK[num_authority];
        System.out.println("The referendum has ended. Waiting for authority connection");
        for (int i = 0; i < num_authority; i++) {
            System.out.println("Waiting for connections...");
            sslSock[i] = (SSLSocket) sSock.accept(); // accept connections
            System.out.println("new connection\n");
            SKAU[i] = ProtocolRecostructionSK(sslSock[i]);
            System.out.println("Partial secret key acquired");
            PartialPK[i] = SKAU[i].getPK();
            sslSock[i].close();
        }
        PKAU = AggregatePartialPublicKeys(PartialPK);
        System.out.println("Scrutiny Phase started");
        protocolRecostruction(SKAU);
        System.out.println("Scrutiny Phase ended");
    }

    private static ElGamalSK ProtocolRecostructionSK(SSLSocket sslSocket) throws Exception {
        InputStream in = sslSocket.getInputStream();
        ElGamalSK SK = null;
        try {

            ObjectInputStream objectIn;

            objectIn = new ObjectInputStream(in);

            SK = (ElGamalSK) objectIn.readObject();

            sslSocket.close(); // close connection
        } catch (Exception e) {
            e.printStackTrace();
        }

        return SK;
    }

    private static ElGamalCT recoveryCT(String ctmsg) {
        String[] parts = ctmsg.split(",");
        return new ElGamalCT(new BigInteger(parts[0]), new BigInteger(parts[1]));
    }

    private static LinkedList<ElGamalCT> listValue() {
        LinkedList<ElGamalCT> list = new LinkedList<>();
        for (Map.Entry<String, String> x : mapSmartContracts.entrySet()) {
            String ctmsg = x.getValue();
            list.add(recoveryCT(ctmsg));
        }
        return list;
    }

    private static BigInteger resultVoting(LinkedList<ElGamalCT> list, ElGamalSK[] SKAU) {
        ElGamalCT CTH = list.get(0);
        for (int i = 1; i < list.size(); i++) {
            CTH = Homomorphism(PKAU, CTH, list.get(i));
        }
        ElGamalCT PartialDecCT = CTH;
        for (int i = 0; i < num_authority - 1; i++) {
            PartialDecCT = PartialDecrypt(PartialDecCT, SKAU[i]);
        }
        return DecryptInTheExponent(PartialDecCT, SKAU[num_authority - 1]);
    }

    private static void protocolRecostruction(ElGamalSK[] SKAU) {
        mapSmartContracts = Utils.readFile(smartContracts);
        LinkedList<ElGamalCT> list = listValue();
        Utils.writeResult("Result.txt", resultVoting(list, SKAU));

    }

}
