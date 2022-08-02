package it.unisa.securityteam;

import java.io.Serializable;
import java.math.BigInteger;

//structure for ElGamal public-key
public class ElGamalPK implements Serializable {

    BigInteger g, h, p, q; // description of the group and public-key h=g^s
    int securityparameter; // security parameter

    public ElGamalPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = h;
        this.securityparameter = securityparameter;

    }
}
