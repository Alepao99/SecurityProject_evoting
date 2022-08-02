package it.unisa.securityteam;


import java.io.Serializable;
import java.math.BigInteger;

//Structure for ElGamal ciphertext
public class ElGamalCT implements Serializable {
	BigInteger C, C2;

	public ElGamalCT(BigInteger C, BigInteger C2) {
        this.C = C;
		this.C2 = C2;

	}

	public ElGamalCT(ElGamalCT CT) {
		this.C = CT.C;
		this.C2 = CT.C2;

	}

}
