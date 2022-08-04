package it.unisa.securityteam;


import java.math.*;
import java.security.*;

public class ElGamal {

    public static ElGamalSK Setup(int securityparameter) {
        BigInteger p, q, g, h;

        SecureRandom sc = new SecureRandom(); // create a secure random source

        while (true) {
            q = BigInteger.probablePrime(securityparameter, sc);
            // method probablePrime returns a prime number of length securityparameter
            // using sc as random source

            p = q.multiply(BigInteger.TWO);
            p = p.add(BigInteger.ONE); // p=2q+1

            if (p.isProbablePrime(50) == true) {
                break; // returns an integer that is prime with prob.
            }// 1-2^-50

        }
// henceforth we have that p and q are both prime numbers and p=2q+1
// Subgroups of Zp* have order 2,q,2q

        g = new BigInteger("4"); // 4 is quadratic residue so it generates a group of order q
// g is a generator of the subgroup the QR modulo p
// in particular g generates q elements where q is prime

        BigInteger s = new BigInteger(securityparameter, sc); // s is the secret-key
        h = g.modPow(s, p); // h=g^s mod p

        ElGamalPK PK = new ElGamalPK(p, q, g, h, securityparameter);

        return new ElGamalSK(s, PK);
    }

    public static ElGamalCT Encrypt(ElGamalPK PK, BigInteger M) {
        SecureRandom sc = new SecureRandom(); // create a secure random source

        BigInteger r = new BigInteger(PK.securityparameter, sc); // choose random r of lenght security parameter
        // C=[h^r*M mod p, g^r mod p].

        BigInteger C = M.multiply(PK.h.modPow(r, PK.p)); // C=M*(h^r mod p)
        C = C.mod(PK.p); // C=C mod p
        BigInteger C2 = PK.g.modPow(r, PK.p); // C2=g^r mod p
        return new ElGamalCT(C, C2); // return CT=(C,C2)

    }

    public static BigInteger Decrypt(ElGamalCT CT, ElGamalSK SK) {
        // C=[C,C2]=[h^r*M mod p, g^r mod p].
        // h=g^s mod p

        BigInteger tmp = CT.C2.modPow(SK.s, SK.PK.p); // tmp=C2^s mod p
        tmp = tmp.modInverse(SK.PK.p);
        // if tmp and p are BigInteger tmp.modInverse(p) is the integer x s.t.
        // tmp*x=1 mod p
        // thus tmp=C2^{-s}=g^{-rs} mod p =h^{-r}

        BigInteger M = tmp.multiply(CT.C).mod(SK.PK.p); // M=tmp*C mod p
        return M;

    }

    public static void main(String[] args) throws Exception {
        // Test El Gamal Encrypt+Decrypt

        {
            ElGamalSK SK = Setup(2048); // in real implementation set security parameter to at least 2048 bits

            System.out.println("Setup for (standard) El Gamal:");
            System.out.println("secret-key = " + SK.s); // print the SK, PK and the group description
            System.out.println("public-key = " + SK.PK.h);
            System.out.println("p = " + SK.PK.p);
            System.out.println("q = " + SK.PK.q);
            System.out.println("g = " + SK.PK.g);

            BigInteger M;
            // M=new BigInteger(SK.PK.securityparameter,sc); // Bob encrypts a random
            // integer M - note: for security we need to guaranteee this integer to be QR
            // modulo p. For this reason
            M = new BigInteger("5");
            M = M.mod(SK.PK.p);

            System.out.println("plaintext to encrypt with (standard) El Gamal = " + M);

            ElGamalCT CT = Encrypt(SK.PK, M); // CT encrypts M

            BigInteger D;
            D = Decrypt(CT, SK);
            System.out.println("decrypted plaintext with (standard) El Gamal = " + D + "\n"); // it should print the
            // same integer as
            // before
        }

    }
}
