package it.unisa.securityteam.project;

import java.io.Serializable;
import java.math.BigInteger;

public class SchnorrSig implements Serializable {

    private BigInteger a, e, z;

    public SchnorrSig(BigInteger a, BigInteger e, BigInteger z) {
        this.a = a;
        this.e = e;
        this.z = z;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getZ() {
        return z;
    }

}
