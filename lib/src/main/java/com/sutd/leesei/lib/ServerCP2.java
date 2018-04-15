package com.sutd.leesei.lib;

/**
 * Created by Nightzsky on 4/15/2018.
 */

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {
    public static byte[] responseFromClient(DataInputStream fromClient){
        try {
            int byteLength = fromClient.readInt();
            byte[] byteReceived = new byte[byteLength];
            fromClient.readFully(byteReceived,0,byteReceived.length);
            return byteReceived;
        }catch (IOException ex){
            ex.printStackTrace();
        }
        return null;
    }

    public static void sendResponseToClient(int packetType,DataOutputStream toClient,byte[] message) throws Exception{
        //byte[] messageByte = message.getBytes();
        toClient.writeInt(packetType);
        toClient.writeInt(message.length);
        toClient.write(message);
        toClient.flush();
    }
    public static PrivateKey getPrivateKey() throws Exception{
        File file = new File("C:\\Users\\Nightzsky\\Downloads\\privateServer.der");
        byte[] privateKeyByte = new byte[(int)file.length()];
        InputStream server = new FileInputStream(file);
        server.read(privateKeyByte);
        server.close();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey serverPrivateKey = keyFactory.generatePrivate(keySpec);
        return serverPrivateKey;

    }

    public static byte[] getServerCertificate() throws Exception{
        File file = new File("C:\\Users\\Nightzsky\\Downloads\\server.crt");
        byte[] serverCertByte = new byte[(int)file.length()];
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
        bis.read(serverCertByte,0,serverCertByte.length);

        return serverCertByte;
    }
    public static void main(String[] args) {

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        SecretKey AES_key = null;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                //This packet mainly dealed with the string message that sent between server and client
                if (packetType == 4) {
                    byte[] messageFromClient = responseFromClient(fromClient);
                    System.out.println("Message From Client: " + new String(messageFromClient));

                    //reply client's initial message
                    if ((new String(messageFromClient)).contains("SecStore")) {
                        sendResponseToClient(4, toClient, "Hello, this is SecStore.".getBytes());
                        System.out.println("Send Response to Client: Hello, this is SecStore!");
                    }

                    //send the certificate to the client
                    else if ((new String(messageFromClient)).contains("certificate signed by CA")) {
                        System.out.println("Sending Certificate!");
                        byte[] serverCertByte = getServerCertificate();
                        System.out.println(new String(serverCertByte));
                        sendResponseToClient(6, toClient, serverCertByte);
                    }

                }
                //This packet mainly deal with the receiving R and sending back encrypting R
                //received R from client and encrypt it using server's private key and send the encrypted R to the client
                else if (packetType == 5) {
                    int R = fromClient.readInt();
                    System.out.println("Received R From Client: " + Integer.toString(R));

                    System.out.println("Encrypting R using private key...");
                    PrivateKey privateKey = getPrivateKey();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                    byte[] Rbyte = BigInteger.valueOf(R).toByteArray();
                    byte[] encryptedR = cipher.doFinal(Rbyte);

                    System.out.println("Sending back the encrypted R to client...");
                    sendResponseToClient(5, toClient, encryptedR);
                    System.out.println("Encrypted R: " + new String(encryptedR));
                }

                //This packet mainly deal with the handshake with the client
                //received handshake from client or bye from client
                else if (packetType == 6) {
                    byte[] responseFromClient = responseFromClient(fromClient);
                    if ((new String(responseFromClient)).contains("Bye")) {
                        System.out.println("Connection closed");
                        //connectionSocket.close();
                    } else if ((new String(responseFromClient)).contains("Handshake")) {
                        System.out.println("Handshake with the client");
                        //sendResponseToClient(0,toClient,"You can start sending the file".getBytes());
                        //  connectionSocket.close();
                    }
                }

                //This packet dealed with the AES session key receive and decryption
                else if (packetType == 2){
                    System.out.println("Receiving encrypted AES key");
                    byte[] encryptedAESkey = responseFromClient(fromClient);
                    System.out.println("Start decrypting the AES key");
                    PrivateKey privateKey = getPrivateKey();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.DECRYPT_MODE,privateKey);
                    byte[] decryptedAESkey = cipher.doFinal(encryptedAESkey);

                    //convert byte[] key to SecretKey Object
                    AES_key = new SecretKeySpec(decryptedAESkey,0,decryptedAESkey.length,"AES");

                }

                // If the packet is for transferring the filename
                else if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    System.out.println(numBytes);
                    byte [] filename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                }

                else if (packetType == 1) {
                    //get server private key to decrypt the file received from client
                    PrivateKey privateKey = getPrivateKey();

                    int numBytes = fromClient.readInt();
                    byte [] block = new byte[numBytes];
                    fromClient.readFully(block, 0, numBytes);

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(block, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                    }
                }

            }
        } catch (Exception e) {e.printStackTrace();}

    }

}
