package it.unisa.securityteam.utility;


import java.io.Serializable;
import java.math.BigInteger;

//Structure for ElGamal ciphertext
public class ElGamalCT implements Serializable {
	private BigInteger C, C2;

	public ElGamalCT(BigInteger C, BigInteger C2) {
        this.C = C;
		this.C2 = C2;

	}

	public ElGamalCT(ElGamalCT CT) {
		this.C = CT.C;
		this.C2 = CT.C2;

	}

    public BigInteger getC() {
        return C;
    }

    public BigInteger getC2() {
        return C2;
    }

    public void setC(BigInteger C) {
        this.C = C;
    }

    public void setC2(BigInteger C2) {
        this.C2 = C2;
    }

}
