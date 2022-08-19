package it.unisa.securityteam.project;


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
            p = p.add(BigInteger.ONE);  // p=2q+1

            if (p.isProbablePrime(50) == true) {
                break;		// returns an integer that is prime with prob.
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

        BigInteger r = new BigInteger(PK.getSecurityparameter(), sc); // choose random r of lenght security parameter
        // C=[h^r*M mod p, g^r mod p].

        BigInteger C = M.multiply(PK.getH().modPow(r, PK.getP())); // C=M*(h^r mod p)
        C = C.mod(PK.getP()); // C=C mod p
        BigInteger C2 = PK.getG().modPow(r, PK.getP());  // C2=g^r mod p
        return new ElGamalCT(C, C2);   // return CT=(C,C2)

    }

    public static ElGamalCT EncryptInTheExponent(ElGamalPK PK, BigInteger m) {
        // identical to Encrypt except that input is an exponent m and encrypts M=g^m mod p

        SecureRandom sc = new SecureRandom();
        BigInteger M = PK.getG().modPow(m, PK.getP()); // M=g^m mod p
        BigInteger r = new BigInteger(PK.getSecurityparameter(), sc);
        BigInteger C = M.multiply(PK.getH().modPow(r, PK.getP())).mod(PK.getP());
        BigInteger C2 = PK.getG().modPow(r, PK.getP());
        return new ElGamalCT(C, C2);

    }

    public static BigInteger Decrypt(ElGamalCT CT, ElGamalSK SK) {
        // C=[C,C2]=[h^r*M mod p, g^r mod p].
        // h=g^s mod p

        BigInteger tmp = CT.getC2().modPow(SK.getS(), SK.getPK().getP());  // tmp=C2^s mod p
        tmp = tmp.modInverse(SK.getPK().getP());
        // if tmp and p are BigInteger tmp.modInverse(p) is the integer x s.t. 
        // tmp*x=1 mod p
        // thus tmp=C2^{-s}=g^{-rs} mod p =h^{-r}

        BigInteger M = tmp.multiply(CT.getC()).mod(SK.getPK().getP()); // M=tmp*C mod p
        return M;

    }

    public static BigInteger DecryptInTheExponent(ElGamalCT CT, ElGamalSK SK) {
        BigInteger tmp = CT.getC2().modPow(SK.getS(), SK.getPK().getP()).modInverse(SK.getPK().getP());
        BigInteger res = tmp.multiply(CT.getC()).mod(SK.getPK().getP());
        // after this step res=g^d for some d in 1,...,q

        BigInteger M = new BigInteger("0");
        while (true) {
            if (SK.getPK().getG().modPow(M, SK.getPK().getP()).compareTo(res) == 0) {
                return M;
            }
// if g^M=res stop and return M
// otherwise M++
            M = M.add(BigInteger.ONE);
        }

    }

    public static SchnorrSig Sign(ElGamalSK SK, String M) {
        SecureRandom sc = new SecureRandom(); // generate secure random source
        BigInteger r = new BigInteger(SK.getPK().getSecurityparameter(), sc); // choose random r
        BigInteger a = SK.getPK().getG().modPow(r, SK.getPK().getP()); // a=g^r mod p
        BigInteger e = HashToBigInteger(SK.getPK(), a, M); // e=H(PK,a,M)
        BigInteger z = r.add(e.multiply(SK.getS()).mod(SK.getPK().getQ())).mod(SK.getPK().getQ()); // z=r+es mod q
        return new SchnorrSig(a, e, z); // (a,e,z) is the signature of M

    }

    public static boolean Verify(ElGamalPK PK, SchnorrSig sigma, String M) {
        // sigma is the triple (a,e,z), PK is the pair (g,h)
        BigInteger e2 = HashToBigInteger(PK, sigma.getA(), M); // e2=H(PK,a,M)
        // crucial that we use the hash computed by ourself and not the challenge e in the signature
        // actually the value e in the signature is NOT needed
        BigInteger tmp = sigma.getA().multiply(PK.getH().modPow(e2, PK.getP()).mod(PK.getP())); // tmp=ah^e2
        if (tmp.compareTo(PK.getG().modPow(sigma.getZ(), PK.getP())) == 0) // compare tmp with g^z mod p
        {
            return true;
        }
        return false;
    }

    public static BigInteger HashToBigInteger(ElGamalPK PK, BigInteger a, String M) {
        // Hash PK+a+M to a BigInteger
        String msg = PK.getG().toString() + PK.getH().toString() + a.toString() + M;
        try { // hash a String using MessageDigest class
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update(Utils.toByteArray(msg));
            BigInteger e = new BigInteger(h.digest());

            return e.mod(PK.getQ());
        } catch (Exception E) {
            E.printStackTrace();
        }

        BigInteger e = new BigInteger("0");
        return e;
    }

    public static ElGamalCT Homomorphism(ElGamalPK PK, ElGamalCT CT1, ElGamalCT CT2) {
        ElGamalCT CT = new ElGamalCT(CT1); // CT=CT1
        CT.setC(CT.getC().multiply(CT2.getC()).mod(PK.getP()));  // CT.C=CT.C*CT2.C mod p
        CT.setC2(CT.getC2().multiply(CT2.getC2()).mod(PK.getP())); // CT.C2=CT.C2*CT2.C2 mod p
        return CT; // If CT1 encrypts m1 and CT2 encrypts m2 then CT encrypts m1+m2

    }

    public static void main(String[] args) throws Exception {
        // Test El Gamal Encrypt+Decrypt

        {
            ElGamalSK SK = Setup(64); // in real implementation set security parameter to at least 2048 bits

            System.out.println("Setup for (standard) El Gamal:");
            System.out.println("secret-key = " + SK.getS()); // print the SK, PK and the group description
            System.out.println("public-key = " + SK.getPK().getH());
            System.out.println("p = " + SK.getPK().getP());
            System.out.println("q = " + SK.getPK().getQ());
            System.out.println("g = " + SK.getPK().getG());

            BigInteger M;
            // M=new BigInteger(SK.PK.securityparameter,sc); // Bob encrypts a random
            // integer M - note: for security we need to guaranteee this integer to be QR
            // modulo p. For this reason
            M = new BigInteger("5");
            M = M.mod(SK.getPK().getP());

            System.out.println("plaintext to encrypt with (standard) El Gamal = " + M);

            ElGamalCT CT = Encrypt(SK.getPK(), M); // CT encrypts M

            BigInteger D;
            D = Decrypt(CT, SK);
            System.out.println("decrypted plaintext with (standard) El Gamal = " + D + "\n"); // it should print the
            // same integer as
            // before
        }

    }
}
