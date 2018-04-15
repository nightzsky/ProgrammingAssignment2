package com.sutd.leesei.lib;

/**
 * Created by Nightzsky on 4/15/2018.
 */

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.print.attribute.standard.JobMessageFromOperator;

import jdk.internal.dynalink.support.TypeConverterFactory;

public class ClientCP1 {

    //get public key from the server cert
    public static PublicKey getPublicKey(X509Certificate serverCert) throws Exception {
        PublicKey serverPubKey = serverCert.getPublicKey();
        return serverPubKey;
    }

    //check if the generated R and decrypted R the same (for authentication of the server)
    public static boolean checkR(int R, byte[] encryptedR,X509Certificate serverCert) throws Exception{
        boolean match = false;
        PublicKey serverPubKey = getPublicKey(serverCert);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,serverPubKey);
        byte[] decryptedR = cipher.doFinal(encryptedR);

        byte[] Rbyte = BigInteger.valueOf(R).toByteArray();
        if (Arrays.equals(Rbyte,decryptedR)){
            match = true;
        }
        return match;
    }

    //check if the server certificate is signed using CA certificate
    public static boolean verifyServerCert(String serverCertString, X509Certificate serverCert) throws Exception{
        boolean verified = false;
        if (serverCertString.contains("Nightzsky")){
            InputStream fis = new FileInputStream("C:\\Users\\Nightzsky\\Downloads\\CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate)cf.generateCertificate(fis);
            PublicKey CAkey = CAcert.getPublicKey();
            fis.close();

            serverCert.checkValidity();
            serverCert.verify(CAkey);

            verified = true;

        }
        return verified;
    }

    //send message to the server
    public static void sendMessageToServer(int packetType, DataOutputStream toServer,byte[] message) throws Exception{
        toServer.writeInt(packetType);
        toServer.writeInt(message.length);
        toServer.write(message);
        toServer.flush();
    }

    //get response from the server
    public static byte[] responseFromServer(DataInputStream fromServer){
        try {
            int byteLength = fromServer.readInt();
            byte[] byteReceived = new byte[byteLength];
            fromServer.readFully(byteReceived,0,byteReceived.length);
            return byteReceived;
        }catch (IOException ex){
            ex.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {

        String filename = "rr.txt";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        int R = 0;
        byte[] encryptedR = null;
        X509Certificate serverCert = null;

        long timeStarted = System.nanoTime();

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            /*
            Before sending file, needs to identify the server that we are connected to is correct
            Authentication
             */

            //first approach to the server
            System.out.println("Authenticating the server...");
            sendMessageToServer(4,toServer,"Hello SecStore, please prove your identity!".getBytes());

            while (!clientSocket.isClosed()) {

                int packetType = fromServer.readInt();

                //communicate with server with string message
                if (packetType == 4) {
                    byte[] messageFromServer = responseFromServer(fromServer);
                    System.out.println("Response From Server: " + new String(messageFromServer));

                    //after receiving first response from server, generate R
                    if ((new String(messageFromServer)).contains("this is SecStore")) {
                        System.out.println("Generating R...");
                        R = (new Random()).nextInt();
                        System.out.println("R generated: " + Integer.toString(R));
                        System.out.println("Sending R to Server...");

                        toServer.writeInt(5);
                        toServer.writeInt(R);
                        toServer.flush();
                    }
                }

                //receiving the encrypted R from the server and start requesting for server signed certificate
                else if (packetType == 5) {
                    encryptedR = responseFromServer(fromServer);
                    System.out.println("Received Encrypted R: " + new String(encryptedR));
                    System.out.println("Requesting signed certificate from server...");
                    sendMessageToServer(4, toServer, "Give me your certificate signed by CA".getBytes());
                }

                //receiving server certificate and check its validity
                else if (packetType == 6) {
                    byte[] serverCertByte = responseFromServer(fromServer);
                    System.out.println("Received Server Signed Certificate!");
                    String serverCertString = new String(serverCertByte);
                    System.out.println(serverCertString);

                    //convert the byte[] certificate to X509 certificate
                    InputStream serverCertInput = new ByteArrayInputStream(serverCertByte);
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    serverCert = (X509Certificate) certificateFactory.generateCertificate(serverCertInput);

                    System.out.println("Verifying Server Certification Now");
                    boolean verified = verifyServerCert(serverCertString, serverCert);

                    System.out.println("Decrypting R now");
                    boolean Rmatch = checkR(R, encryptedR, serverCert);

                    if (verified && Rmatch) {
                        System.out.println("The server is verified!");
                        System.out.println("Handshake with the server");
                        sendMessageToServer(6, toServer, "Handshake".getBytes());
                        break;
                    } else {
                        System.out.println("Fail to verify the server's certificate. Closing connection...");
                        sendMessageToServer(6, toServer, "Bye!".getBytes());
                        clientSocket.close();
                        System.out.println("Connection Closed!");
                    }

                }
            }

            System.out.println("Getting public key from the server certificate...");
            //get public key from the server certificate for encryption
            PublicKey publicKey = getPublicKey(serverCert);
            System.out.println("Done retrieving the public key!");

            System.out.println("Sending file...");

            // Send the filename
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            System.out.println(filename.getBytes().length);
            toServer.write(filename.getBytes());
            //toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];


            // Send the file
            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;

                toServer.writeInt(1);
                toServer.writeInt(numBytes);
                toServer.write(fromFileBuffer);
                toServer.flush();
            }

            bufferedFileInputStream.close();
            fileInputStream.close();


            System.out.println("Closing connection...");


        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }


}