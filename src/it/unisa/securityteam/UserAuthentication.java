/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package it.unisa.securityteam;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 *
 * @author apaolillo
 */
public class UserAuthentication {

    private static void Protocol(SSLSocket userSock) throws Exception {
        OutputStream out = userSock.getOutputStream();
        InputStream in = userSock.getInputStream();

        try {
            ObjectOutputStream objectOut;
            objectOut = new ObjectOutputStream(out);

            ObjectInputStream inputStream;
            inputStream = new ObjectInputStream(in);
            Scanner scanner = new Scanner(System.in);

            System.out.println((String) inputStream.readObject());
            String fiscalCode = scanner.next();
            objectOut.writeObject(fiscalCode);

            System.out.println((String) inputStream.readObject());
            String userName = scanner.next();
            objectOut.writeObject(userName);
            
            String check = (String) inputStream.readObject();
            System.out.println(check);
            if (check.compareToIgnoreCase("User present in database ") == 0) {
                int repetition = 3;
                check = "";
                while (repetition > 0) {
                    check = (String) inputStream.readObject();
                    System.out.println(check);
                    String psw = scanner.next();
                    objectOut.writeObject(psw);
                    if (check.compareToIgnoreCase("You have access!") == 0) {
                        break;
                    }
                    repetition--;
                    if (repetition == 0) {
                        System.out.println((String) inputStream.readObject());

                    } else {
                        System.out.println((String) inputStream.readObject());
                    }

                }
            } else {
                System.out.println((String) inputStream.readObject());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        userSock.close();
        System.out.println("Sessione chiusa");
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        SSLSocketFactory sockfact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket userSock = (SSLSocket) sockfact.createSocket("localhost", 4000);
        userSock.startHandshake();
        Protocol(userSock);
    }

}
