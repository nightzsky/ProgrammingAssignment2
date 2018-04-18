package com.sutd.leesei.lib;

/*
    Author: Siow Lee Sei(1002257), Ong Jing Xuan(1002065)
*/

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {

    //receive the response from the client
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

    //send the response to the client
    public static void sendResponseToClient(int packetType,DataOutputStream toClient,byte[] message) throws Exception{
        toClient.writeInt(packetType);
        toClient.writeInt(message.length);
        toClient.write(message);
        toClient.flush();
    }

    //get the private key from the server certificate
    public static PrivateKey getPrivateKey() throws Exception{
        //File file = new File("C:\\Users\\Nightzsky\\Downloads\\privateServer.der");
        File file = new File("privateServer.der");
        byte[] privateKeyByte = new byte[(int)file.length()];
        InputStream server = new FileInputStream(file);
        server.read(privateKeyByte);
        server.close();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey serverPrivateKey = keyFactory.generatePrivate(keySpec);
        return serverPrivateKey;

    }

    //get the server certificate
    public static byte[] getServerCertificate() throws Exception{
        File file = new File("server.crt");
        //File file = new File("C:\\Users\\Nightzsky\\Downloads\\server.crt");
        byte[] serverCertByte = new byte[(int)file.length()];
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
        bis.read(serverCertByte,0,serverCertByte.length);

        return serverCertByte;
    }

    public static void main(String[] args) {

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        int totalFileSize = 0;
        int receivedFileSize = 0;
        String originalFilename = null;
        String decryptedFilename = null;

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
                    } else if ((new String(responseFromClient)).contains("Handshake")) {
                        System.out.println("Handshake with the client");

                    }
                }

                //This packet deal with the AES session key receive and decryption
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
                    totalFileSize = fromClient.readInt();
                    System.out.println(numBytes);
                    byte [] filename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    originalFilename = new String(filename,0,numBytes);
                    decryptedFilename = "recv_"+originalFilename;

                    fileOutputStream = new FileOutputStream(decryptedFilename);
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                }

                //This packet deal with the file content
                else if (packetType == 1) {
                    //get server private key to decrypt the file received from client
                    Cipher AEScipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    AEScipher.init(Cipher.DECRYPT_MODE,AES_key);

                    int numBytes = fromClient.readInt();


                    byte [] block = new byte[numBytes];
                    fromClient.readFully(block, 0, numBytes);

                    byte[] decryptedFile = AEScipher.doFinal(block);
                    bufferedFileOutputStream.write(decryptedFile,0,decryptedFile.length);

                    receivedFileSize += decryptedFile.length;

                    if (receivedFileSize == totalFileSize){
                        break;
                    }

                }


            }
                //inform the client that it's done and close all the connection and stream
                sendResponseToClient(3,toClient,"Done".getBytes());
                fileOutputStream.close();
                bufferedFileOutputStream.close();
                fromClient.close();
                toClient.close();
                connectionSocket.close();

            //check if the original file and decrypted file the same
            int flag = checkFile(originalFilename,decryptedFilename);
            System.out.println(flag);
        } catch (Exception e) {e.printStackTrace();}

    }

    //compare the original file and decrypted file
    public static int checkFile(String originalFile, String decryptedFile) throws Exception{
        File f1 = new File(originalFile);// OUTFILE
        File f2 = new File(decryptedFile);// INPUT

        FileReader fR1 = new FileReader(f1);
        FileReader fR2 = new FileReader(f2);

        BufferedReader reader1 = new BufferedReader(fR1);
        BufferedReader reader2 = new BufferedReader(fR2);

        String line1 = null;
        String line2 = null;
        int flag = 1;
        while ((flag == 1) && ((line1 = reader1.readLine()) != null)
                && ((line2 = reader2.readLine()) != null)) {
            if (!line1.equals(line2))
                flag = 0;
        }
        reader1.close();
        reader2.close();
        System.out.println("Flag " + flag);
        return flag;
    }


}
