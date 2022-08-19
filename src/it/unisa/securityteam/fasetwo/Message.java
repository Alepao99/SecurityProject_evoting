/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package it.unisa.securityteam.fasetwo;

import it.unisa.securityteam.utility.ElGamalCT;
import java.io.Serializable;
import java.math.BigInteger;

/**
 *
 * @author apaolillo
 */
public class Message implements Serializable{
    private String ts;
    private ElGamalCT x;
    private BigInteger R;

    public Message(String ts, ElGamalCT x, BigInteger R) {
        this.ts = ts;
        this.x = x;
        this.R = R;
    }

    public String getTs() {
        return ts;
    }

    public void setTs(String ts) {
        this.ts = ts;
    }

    public ElGamalCT getX() {
        return x;
    }

    public void setX(ElGamalCT x) {
        this.x = x;
    }

    public BigInteger getR() {
        return R;
    }

    public void setR(BigInteger R) {
        this.R = R;
    }

    @Override
    public String toString() {
        return ts + ";" + x + ";" + R;
    }
    
}
