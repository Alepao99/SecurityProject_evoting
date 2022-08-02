package it.unisa.securityteam;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Voter extends ElGamal { // Voter reads the public key from the file PublicKey.txt and then
    // uses it to encrypt his vote. Finally, Voter sends his hashed id
    // and his encrypted vote to Server 1

    static void Protocol(SSLSocket sSock, String id_voter) throws Exception {
        OutputStream out = sSock.getOutputStream();
        try {
            ObjectOutputStream outputStream;
            outputStream = new ObjectOutputStream(out);
            outputStream.writeObject(id_voter);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void Protocol1(SSLSocket sSock, ElGamalCT CT) throws Exception {
        OutputStream out = sSock.getOutputStream();
        try {
            ObjectOutputStream outputStream;
            outputStream = new ObjectOutputStream(out);
            outputStream.writeObject(CT);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception {

        FileReader filein = new FileReader("PublicKey.txt");
        BufferedReader filebuf = new BufferedReader(filein);
        BigInteger p = new BigInteger(filebuf.readLine());
        BigInteger q = new BigInteger(filebuf.readLine());
        BigInteger g = new BigInteger(filebuf.readLine());
        BigInteger h = new BigInteger(filebuf.readLine());
        filebuf.close();

        ElGamalPK PK = new ElGamalPK(p, q, g, h, 2048);
        System.out.println("Public key letta:");
        System.out.println("p = " + PK.p);
        System.out.println("q =" + PK.q);
        System.out.println("g = " + PK.g);
        System.out.println("h = " + PK.h);

        String fiscalCode = "LMBMRP99E65A509N";

        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(Utils.toByteArray(fiscalCode));
        byte[] temp = hash.digest();
        String id_voter = Utils.toHex(temp);

        BigInteger vote = new BigInteger("1"); // vote
        System.out.println("Voto espresso: " + vote.toString());

        ElGamalCT CT = Encrypt(PK, vote); // encrypt vote in CT
        System.out.println("Voto cifrato:");
        System.out.println("C = " + CT.C);
        System.out.println("C2 = " + CT.C2);

        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket cSock = (SSLSocket) sockfact.createSocket("localhost", 4000);
        cSock.startHandshake();

        Protocol(cSock, id_voter);
        Protocol1(cSock, CT);
        cSock.close();
        System.out.println("Sessione chiusa");

    }

}
