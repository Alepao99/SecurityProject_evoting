package it.unisa.securityteam.project;

import java.io.Serializable;
import java.math.BigInteger;

//structure for ElGamal public-key
public class ElGamalPK implements Serializable {

    private BigInteger g, h, p, q; // description of the group and public-key h=g^s
    private int securityparameter; // security parameter

    public ElGamalPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = h;
        this.securityparameter = securityparameter;

    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public int getSecurityparameter() {
        return securityparameter;
    }
    
}
