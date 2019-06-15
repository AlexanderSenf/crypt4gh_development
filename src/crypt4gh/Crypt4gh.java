/*
 * Copyright 2019 Alexander Senf
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package crypt4gh;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.X25519;
import static com.google.crypto.tink.subtle.X25519.computeSharedSecret;
import static com.google.crypto.tink.subtle.X25519.generatePrivateKey;
import static com.google.crypto.tink.subtle.X25519.publicFromPrivate;
import com.rfksystems.blake2b.Blake2b;
import com.rfksystems.blake2b.security.Blake2bProvider;
import crypt4gh.dto.DataKeyContent;
import crypt4gh.dto.DataPacket;
import crypt4gh.dto.EditListContent;
import crypt4gh.dto.Header;
import crypt4gh.dto.HeaderPacket;
import crypt4gh.dto.PrivateKey;
import crypt4gh.dto.UnencryptedHeader;
import crypt4gh.util.Glue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.io.UnsupportedEncodingException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author asenf
 * 
 * Proof-of-concept implementation of Crypt4GH File Format proposal
 * 
 */
public class Crypt4gh {

    // 'crypt4gh' version 1
    public static byte[] MagicNumber = new byte[] {99, 114, 121, 112, 116, 52, 103, 104};
    public static byte[] Version = new byte[] {1, 0, 0, 0};
    
    public static byte[] HeaderMethod = new byte[] {0, 0, 0, 0};
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Options options = new Options();
        HelpFormatter formatter = new HelpFormatter();

        // Command Line Options
        options.addOption("e", "encrypt", false, "encrypt source");
        options.addOption("d", "decrypt", false, "decrypt source");
        options.addOption("f", "file", true, "file source path");
        options.addOption("o", "output", true, "output file path");
        //options.addOption("k", "key", true, "data key");
        options.addOption("rk", "privatekey", true, "private key file path");
        options.addOption("rkp", "privatekeypass", true, "private key file passphrase");
        options.addOption("uk", "publickey", true, "public key file path");
        options.addOption("ukp", "publickeypass", true, "public key file passphrase");
        options.addOption("gk", "genkey", true, "generate a public/private key pair");
        options.addOption("gkp", "genkeypass", true, "encrypt private key with this passphrase");

        options.addOption("t", "testme", false, "test the operations of the algorithm");

        options.addOption("debug", "debug", false, "print debug information during encryption/decryption");
        boolean debug = false;
        
        // Parse Command Line
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse( options, args);

            if (cmd.hasOption("debug")) {
                debug = true;
            }
            
            if (cmd.hasOption("t")) {
                testMe(debug);
                System.exit(1);                
            }
            
            if (cmd.hasOption("gk")) {
                String keyName = cmd.getOptionValue("gk");
                String keyPassphrase = null;
                if (cmd.hasOption("gkp")) {
                    keyPassphrase = cmd.getOptionValue("gkp");
                }
                genKeys(keyName, keyPassphrase);
                System.exit(1);                
            }
            
            // Input File Path
            Path inputPath = null;
            if (cmd.hasOption("f")) {
                String filePath = cmd.getOptionValue("f");
                inputPath = Paths.get(filePath);
                if (inputPath==null) {
                    System.exit(1);
                }
            }

            // Output File Path
            Path outputFilePath = null;
            if (cmd.hasOption("o")) {
                String filePath = cmd.getOptionValue("o");
                outputFilePath = Paths.get(filePath);
                if (outputFilePath==null) {
                    System.exit(2);
                }
            }

            // Private Key
            Path privateKeyPath = null;
            String privateKeyPassphrase = null;
            if (cmd.hasOption("rk")) {
                String filePath = cmd.getOptionValue("rk");
                privateKeyPath = Paths.get(filePath);
                if (privateKeyPath==null) {
                    System.exit(3);
                } else {
                    if (cmd.hasOption("rkp")) {
                        privateKeyPassphrase = cmd.getOptionValue("rkp");
                    }                    
                }
            }

            // Public Key
            Path publicKeyPath = null;
            String publicKeyPassphrase = null;
            if (cmd.hasOption("uk")) {
                String filePath = cmd.getOptionValue("uk");
                publicKeyPath = Paths.get(filePath);
                if (publicKeyPath==null) {
                    System.exit(3);
                } else {
                    if (cmd.hasOption("ukp")) {
                        publicKeyPassphrase = cmd.getOptionValue("ukp");
                    }                    
                }
            }

            // Load Keys (support unencrypted private keys, allow specification of a public key)
            byte[] privateKey = (privateKeyPassphrase!=null)?
                        loadEncryptedKey(privateKeyPath, privateKeyPassphrase):
                        loadKey(privateKeyPath);
            byte[] publicKey = (publicKeyPath!=null)?
                        loadKey(publicKeyPath):
                        null;
            
            // Detect Mode (Encrypt or Decrypt) and act on it ******************
            if (cmd.hasOption("e")) { // encrypt
                //String key = cmd.getOptionValue("e");
                byte[] key = Glue.getInstance().GenerateRandomString(24, 48, 7, 7, 7, 3);
                int encryptionType = 0;        

                encrypt(inputPath, outputFilePath, encryptionType, key, privateKey, publicKey, debug);
            } else if (cmd.hasOption("d")) { // decrypt
                decrypt(inputPath, outputFilePath, privateKey, publicKey, debug);
            } // ***************************************************************
            
        } catch (ParseException ex) {
            formatter.printHelp( "java -jar crypt4gh.jar", options, true );            
            System.out.println("Unrecognized Parameter. " + ex.getLocalizedMessage());
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            formatter.printHelp( "java -jar crypt4gh.jar", options, true );            
            System.out.println("File IO Exception. " + ex.getLocalizedMessage());
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            System.out.println("File Exception. " + ex.getLocalizedMessage());
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Progressed to this point without errors: Done!
    }
    
    /*
     * Encrypt
     */
    private static void encrypt(Path source, 
                                Path destination, 
                                int encryptionType,
                                byte[] dataKey,
                                byte[] privateKey, // My Private
                                byte[] publicKey,  // Other Public
                                boolean debug) throws IOException, 
                                                      NoSuchAlgorithmException, 
                                                      NoSuchPaddingException, 
                                                      InvalidKeyException, 
                                                      InvalidAlgorithmParameterException, 
                                                      GeneralSecurityException  {        
        // Establish Output Stream
        OutputStream os = Files.newOutputStream(destination);
        if (debug) System.out.println("Writing output to: " + destination);

        // Data Key: Id not specified, auto-generate a private key on the spot
        // [Or generate s shared key between two randomly generated keys]
        if ((dataKey == null) || (dataKey.length!=32)) {
            dataKey =  X25519.generatePrivateKey();
        }
        Base64 b = new Base64();
        if (debug) System.out.println("Data Key:\t" + Hex.encode(dataKey) + "\t" + b.encodeToString(dataKey));

        List<HeaderPacket> headerPackets = new ArrayList<>(); 

        // Generate DataKeyHeader
        DataKeyContent dataKeyContent = new DataKeyContent(0, 0, dataKey);
        // Generate Header Packet for target user 
        HeaderPacket keyPacket = new HeaderPacket(0, privateKey, publicKey, dataKeyContent);        
        headerPackets.add(keyPacket);
        
        // Edit List -- None here
        // TEST [remove] *******************************************************
//        long[] editList = {20L, 10L};
//        EditListContent editListContent = new EditListContent(editList);
        // Generate Header Packet for target user 
//        HeaderPacket editPacket = new HeaderPacket(0, privateKey, publicKey, editListContent);        
//        headerPackets.add(editPacket);
        // TEST [remove] *******************************************************
        
        // Construct unencrypted Header
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(Crypt4gh.MagicNumber,
                                                                    Crypt4gh.Version,
                                                                    headerPackets.size());
        
        // Construct full Header
        Header header = new Header(unencryptedHeader, headerPackets);
        byte[] fullHeaderBytes = header.getBytes();
        
        /*
         * Header is now constructed! Can write it to output stream
         */
        os.write(fullHeaderBytes);
        
        //
        // Header is written. Write actual file data
        //
        
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65536];
        
        /*
         * Main Encryption Loop: Process data in 64K blocks, handle Checksum
         */
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            // Prepare data to be encrypted
            byte[] to_enc = Arrays.copyOf(segment, seg_len);

            // Get next data segment
            seg_len = in.read(segment);
            
            // Encrypt
            byte[] encrypted = (new DataPacket(to_enc, dataKey)).getBytes();
            if (debug) {
                byte[] nonce = Arrays.copyOfRange(encrypted, 0, 12);
                System.out.println("Segment Nonce 1:\t" + Hex.encode(nonce) + "\t" + b.encodeToString(nonce));
            } 
            
            // Write data to output stream
            os.write(encrypted);
        }
        in.close();
        
        os.flush();
        os.close();
    }

    private static byte[] intToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    
    
    /*
     * Decrypt
     */
    private static void decrypt(Path source, 
                                Path destination, 
                                byte[] privateKey, // My Private
                                byte[] publicKey,  // Other Public
                                boolean debug) throws IOException, 
                                                      NoSuchAlgorithmException, 
                                                      NoSuchPaddingException, 
                                                      InvalidKeyException, 
                                                      InvalidAlgorithmParameterException, 
                                                      GeneralSecurityException,
                                                      Exception  {
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        if (debug) System.out.println("Input Path: " + source);
        
        // Read unencrypted file Header (validates Magic Number & Version)
        Header header = getHeader(in);
        if (debug) {
            System.out.println("data key: " + Hex.encode(header.getDataKey(privateKey)));
        }
                
        // Get Data Key
        byte[] dataKey = header.getDataKey(privateKey);
        
        // Get Edit List (if one is there)
        boolean skip = false, range = false;
        int editIndex = 0;
        long[] editList = header.getEditList(privateKey);
        if (editList != null && editList.length > 0) {
            range = true;
            skip = true;
        }
        
        // Decrypt Data
        // Public Key - specified in File
        if (publicKey == null) {
            publicKey = header.getSourcePublicKey();
        }
        Base64 b = new Base64();
        if (debug) System.out.println("Encrypter Public Key:\t" + Hex.encode(publicKey) + "\t" + b.encodeAsString(publicKey));
        
        //  Create Output Stream
        OutputStream out = Files.newOutputStream(destination);
        if (debug) System.out.println("Output Path: " + destination);
 
        // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Decrypt Loop
        // Encrypt - in 64KiB segments
        int segmentSize = 65536 + 12 + 16;
        byte[] segment = new byte[segmentSize]; // 64KiB + nonce (12) + mac (16) [ + range (8)]
        
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            byte[] sub_seg = Arrays.copyOfRange(segment, 0, seg_len); // -rangeDelta
            
            // Get next segment
            seg_len = in.read(segment);
            
            if (debug) {
                System.out.println("seg len: " + seg_len);
                byte[] iv_ = new byte[12];
                System.arraycopy(sub_seg, 0, iv_, 0, 12);
                System.out.println("iv: " + Hex.encode(iv_));
                byte[] mac_ = new byte[16];
                System.arraycopy(sub_seg, 65547, mac_, 0, 16);
                System.out.println("mac: " + Hex.encode(mac_));
            }
            

            // Decrypt data
            byte[] decrypted = cipher.decrypt(sub_seg, new byte[0]); // should be 64KiB

            // Process Range Bytes
            byte[] decrypted_range = null;
            int position = 0;
            while (position < decrypted.length) {
                if (range) { // respect range instruction
                    int remain = decrypted.length - position;
                    if (skip) { // 'Skip' mode: ignore specified number of bytes (or until the end)
                        if (editIndex >= editList.length) { // past last range
                            position += remain;
                            remain = 0;
                            decrypted_range = null;
                        } else if (editList[editIndex] > remain) { // ignore current content
                            editList[editIndex] = editList[editIndex] - remain;
                            decrypted_range = null;
                        } else {
                            position += editList[editIndex];                           
                            remain = (int) (remain - editList[editIndex]);
                            editList[editIndex] = 0;
                            skip = false;
                            editIndex++;
                            decrypted_range = null;
                        }
                    } else { // 'use' mode: Use specified number of bytes (or until the end)
                        if (editIndex >= editList.length) { // past last range
                            decrypted_range = Arrays.copyOfRange(decrypted, position, (position + remain));
                            position += remain;
                            remain = 0;                            
                        } else if (editList[editIndex] > remain) {
                            decrypted_range = Arrays.copyOfRange(decrypted, position, (position + remain));
                            position += remain;
                        } else {
                            decrypted_range = Arrays.copyOfRange(decrypted, position, (position + (int) editList[editIndex]) );
                            remain = (int) (remain - editList[editIndex]);
                            editList[editIndex] = 0;
                            skip = true;
                            editIndex++;
                        }
                    }
                } else { // use everything
                    decrypted_range = decrypted;
                    position = decrypted.length;
                }
                
                if (decrypted_range != null)
                    out.write(decrypted_range);
                
            }
            
            // Write decryted data to output stream
    //        out.write(decrypted_range);
        }
         
        // Done: Close Streams
        in.close();
        out.flush();
        out.close();
    }
    private static int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /*
     * Function to read the unencrypted header of an encrypted file
     */
    private static UnencryptedHeader getUnencryptedHeader(InputStream source) throws Exception {
        byte[] header = new byte[52];
        source.read(header);

        // Generate Header Object
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(ByteBuffer.wrap(header));
        
        // Validate File Magic Number & Version
        if (!unencryptedHeader.equalsMagicNumber(MagicNumber)) {
            throw new Exception("This is not a CRYPT4GH File.");
        }
        
        // Validate Crypt4GH Version
        if (!unencryptedHeader.equalsVersion(Version)) {
            throw new Exception("Incorrect CRYPT4GH Version.");
        }
        
        return unencryptedHeader;
    }
        
    // Extract Header Structure from 
    private static Header getHeader(InputStream in) throws IOException {
        //int x = 0;
        
        // Get unencrypted Header.
        byte[] startUnencrypted = new byte[UnencryptedHeader.UNENCRYPTEDHEADERLENGTH];
        in.read(startUnencrypted);
        //x += UnencryptedHeader.UNENCRYPTEDHEADERLENGTH;
        UnencryptedHeader unencrytedHeader = new UnencryptedHeader(startUnencrypted);
        
        // Allow Peeking
        PushbackInputStream pbis = new PushbackInputStream(in, 4);
        
        // Loop Through Header Packets
        List<HeaderPacket> headerPackets = new ArrayList<>();
        for (int i=0; i<unencrytedHeader.getHeaderPacketCount(); i++) {
            // Determine Packet Length
            byte[] packetLengthBytes = new byte[4];
            pbis.read(packetLengthBytes);
            int packetLength = getLittleEndian(packetLengthBytes);
            pbis.unread(packetLengthBytes);
            
            // Read Packet
            byte[] onePacketBytes = new byte[packetLength];
            pbis.read(onePacketBytes);
            //x += packetLength;
            
            HeaderPacket oneHeaderPacket = new HeaderPacket(onePacketBytes);
            headerPackets.add(oneHeaderPacket);
        }
        //if (true) {
        //    System.out.println("Header: " + x + " bytes");
        //}
        
        // Build Header
        Header header = new Header(unencrytedHeader, headerPackets);
        
        return header;
    }
    
    
    private static byte[] getKey(char[] password) {
        SecretKey secret = Glue.getInstance().getKey(password, 256);
        return secret.getEncoded();
    }
    
    // Incomplete!
    private static void generateX25519Key(Path keyOut) throws IOException {
        byte[] generatePrivateKey = X25519.generatePrivateKey();

        FileWriter out = new FileWriter(keyOut.toString());
        Base64 encoder = new Base64(64);
        
        String key_begin = "-----BEGIN PRIVATE KEY-----\n";
        String end_key = "-----END PRIVATE KEY-----";

        // Todo: ANS.1 Format
        
        String pemKeyPre = new String(encoder.encode(generatePrivateKey));
        String pemKey = key_begin + pemKeyPre + end_key;        
        try {
            out.write(pemKey);
        } finally {
            out.close();
        }
    }

    private static byte[] getSharedKey(byte[] myPrivate, byte[] userPublic) throws InvalidKeyException {
        byte[] computeSharedSecret = X25519.computeSharedSecret(myPrivate, userPublic);
        return computeSharedSecret;
    }

    private static byte[] loadKey(Path keyIn) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        BufferedReader in = new BufferedReader(new FileReader(keyIn.toString()));
        in.readLine();
        String key = in.readLine();
        in.readLine();
        in.close();
        
        Base64 decoder = new Base64(64);
        byte[] decode = decoder.decode(key); //.substring(20));
        
//        ByteArrayInputStream bain = new ByteArrayInputStream(decode);
//        ASN1InputStream ais = new ASN1InputStream(bain);
//        while (ais.available() > 0) {
//            ASN1Primitive obj = ais.readObject();
//            
//            System.out.println(ASN1Dump.dumpAsString(obj, true));
//        }        
        return decode;
    }
    private static byte[] loadEncryptedKey(Path keyIn, String keyPassIn) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, GeneralSecurityException {
        BufferedReader in = new BufferedReader(new FileReader(keyIn.toString()));
        in.readLine();
        String key = in.readLine();
        in.readLine();
        in.close();
                
        Base64 decoder = new Base64();
        byte[] decode = decoder.decode(key); //.substring(20));
        PrivateKey pk = new PrivateKey(decode, keyPassIn);
        
//        String decodeString = new String(decode);
//        PrivateKey pk = new PrivateKey(decodeString, keyPassIn);
        
//        ByteArrayInputStream bain = new ByteArrayInputStream(decode);
//        ASN1InputStream ais = new ASN1InputStream(bain);
//        while (ais.available() > 0) {
//            ASN1Primitive obj = ais.readObject();
//            
//            System.out.println(ASN1Dump.dumpAsString(obj, true));
//        }

        return pk.getKey();
    }

    /*
     * Key Generation function
     * 
     * Generate a .pub and a .sec file with keys.
     */
    private static void genKeys(String keyName, String keyPassphrase) throws InvalidKeyException, FileNotFoundException, GeneralSecurityException, NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
        byte[] privateKey = generatePrivateKey();
        byte[] publicFromPrivate = publicFromPrivate(privateKey);

        Base64 b = new Base64();
        
        PrintWriter prkf = new PrintWriter(keyName.concat(".sec"));
        if (keyPassphrase == null) {
            prkf.println("-----BEGIN PRIVATE KEY-----");
            prkf.println(b.encodeAsString(privateKey));
            prkf.print("-----END PRIVATE KEY-----");
        } else {
            prkf.println("-----BEGIN ENCRYPTED PRIVATE KEY-----");
            PrivateKey pk = new PrivateKey(privateKey, keyPassphrase, "bcrypt");
            prkf.println(b.encodeAsString(pk.getKeyBytes()));
            prkf.print("-----END ENCRYPTED PRIVATE KEY-----");
        }
        prkf.close();
        
        PrintWriter pbkf = new PrintWriter(keyName.concat(".pub"));
        pbkf.println("-----BEGIN CRYPT4GH PUBLIC KEY-----");
        pbkf.println(b.encodeAsString(publicFromPrivate));
        pbkf.print("-----END CRYPT4GH PUBLIC KEY-----");
        pbkf.close();
    }
    
    /*
     * Hashing function to derive the actual shared key after X25519 multiplication
     */
    private static byte[] Blake2B_512(byte[] k_sharedKey, 
                                      byte[] otherPublicKey, 
                                      byte[] myPublicKey,
                                      boolean debug) throws NoSuchAlgorithmException {
        Security.addProvider(new Blake2bProvider());    
        
        byte[] combined = new byte[96];
        System.arraycopy(k_sharedKey, 0, combined, 0, 32);
        System.arraycopy(otherPublicKey, 0, combined, 32, 32);
        System.arraycopy(myPublicKey, 0, combined, 64, 32);
        
        byte[] digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_512).digest(combined);

        if (debug) {
            System.out.println("Blake2b 1st 32 bytes: " + Hex.encode(Arrays.copyOfRange(digest, 0, 32)));
            System.out.println("Blake2b 2nd 32 bytes: " + Hex.encode(Arrays.copyOfRange(digest, 32, 64)));
        }
        
        return Arrays.copyOfRange(digest, 0, 32);
    }
    
    /*
     * just a test run: encrypting and decrypting a file with randomly generated key pairs
     */
    private static void testMe(boolean debug) throws GeneralSecurityException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
        // Party 1 (Encrypter), Party 2 (Recipient)
        byte[] privateKey_party1 = generatePrivateKey();
        byte[] publicFromPrivate_party1 = publicFromPrivate(privateKey_party1);
        byte[] privateKey_party2 = generatePrivateKey();
        byte[] publicFromPrivate_party2 = publicFromPrivate(privateKey_party2);

        // Random shared key..
        byte[] dataKey = computeSharedSecret(privateKey_party2, publicFromPrivate_party1);

        // Test to be Encrypted
        String testText = "This is a test string.";
        
        // Create temporary files (1) Origin, (2) encrypted, (3) decrypted.
        File tempFile1 = File.createTempFile("crypt4ghTest_source-", ".tmp");
        tempFile1.deleteOnExit();
        File tempFile2 = File.createTempFile("crypt4ghTest_encrypt-", ".tmp");
        tempFile2.deleteOnExit();
        File tempFile3 = File.createTempFile("crypt4ghTest_decrypt-", ".tmp");
        tempFile3.deleteOnExit();
        
        // Write test String to source
        FileWriter source = new FileWriter(tempFile1);
        source.write(testText);
        source.close();
        
        // Call encryption function 
        encrypt(tempFile1.toPath(), 
                tempFile2.toPath(), 
                0,
                dataKey,
                privateKey_party1,
                publicFromPrivate_party2,
                debug);
        
        // This should have generted the encrypted file..
        System.out.println();
        
        // Now decrypt it :)
        decrypt(tempFile2.toPath(), 
                tempFile3.toPath(), 
                privateKey_party2,
                publicFromPrivate_party1,
                debug);
        
        // The file should be decrypted...
        System.out.println();
        
        
    }
    
    private static byte[] decrypt(byte[] cipherText, String encryptionKey, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey secret = Glue.getInstance().getKey(encryptionKey.toCharArray(), 128);
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(IV));
        return cipher.doFinal(cipherText);
    }
    
    private static byte[] encrypt(int start, int end, String encryptionKey, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey secret = Glue.getInstance().getKey(encryptionKey.toCharArray(), 128);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(IV));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStream out = new CipherOutputStream(baos, cipher);
        byte[] sT = intToLittleEndian(start);
        out.write(sT);
        byte[] eT = intToLittleEndian(end);                
        out.write(eT);

        byte[] encryptedrange = baos.toByteArray();
        return encryptedrange;
    }
}
