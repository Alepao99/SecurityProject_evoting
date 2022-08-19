package it.unisa.securityteam.utility;

import java.io.Serializable;
import java.math.BigInteger;

//structure for ElGamal secret-key
public class ElGamalSK implements Serializable { // Secret-key of El Gamal

    private BigInteger s;
    // s is random BigInteger from 1 to q where q is the order of g (g is in the PK)

    private ElGamalPK PK; // PK of El Gamal

    public ElGamalSK(BigInteger s, ElGamalPK PK) {
        this.s = s;
        this.PK = PK;

    }

    public BigInteger getS() {
        return s;
    }

    public ElGamalPK getPK() {
        return PK;
    }
    
}
