/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package it.unisa.securityteam;

import java.io.Serializable;

/**
 *
 * @author apaolillo
 */
class User implements Serializable {

    private String userName;
    private String fiscalCode;
    private String psw;

    public User(String userName, String fiscalCode, String psw) {
        this.userName = userName;
        this.fiscalCode = fiscalCode;
        this.psw = psw;
    }

    public String getUserName() {
        return userName;
    }

    public String getFiscalCode() {
        return fiscalCode;
    }

    public String getPsw() {
        return psw;
    }

    @Override
    public String toString() {
        return "User{" + "userName=" + userName + ", fiscalCode=" + fiscalCode + ", psw=" + psw + '}';
    }
}
