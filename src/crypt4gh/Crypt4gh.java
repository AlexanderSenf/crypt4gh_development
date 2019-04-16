/*
 * Copyright 2018 ELIXIR EBI
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

import crypt4gh.dto.EncryptedHeader;
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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

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
        options.addOption("tk", "testmekey", false, "test the operations of the algorithm");

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
            if (cmd.hasOption("tk")) {
                testMeKey();
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

                //encrypt(inputPath, outputFilePath, encryptionType, key, privateKey, publicKey, debug);
                encryptSubranges(inputPath, outputFilePath, encryptionType, key, privateKey, publicKey, debug);
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

        // Generate Unencrypted Header
        byte[] ownPublicKey = publicFromPrivate(privateKey);
        
        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey_forBlake2b = getSharedKey(privateKey, publicKey);
        byte[] sharedKey = Blake2B_512(sharedKey_forBlake2b, publicKey, ownPublicKey, debug );
        Base64 b = new Base64();
        if (debug) {
            System.out.println("Own Private Key:\t" + Hex.encode(privateKey) + "\t" + b.encodeToString(privateKey));
            System.out.println("Own Public Key:\t" + Hex.encode(X25519.publicFromPrivate(privateKey)) + "\t" + b.encodeToString(X25519.publicFromPrivate(privateKey)));
            System.out.println("Target Public Key:\t" + Hex.encode(publicKey) + "\t" + b.encodeToString(publicKey));
            System.out.println("Pre Shared Key:\t" + Hex.encode(sharedKey_forBlake2b) + "\t" + b.encodeAsString(sharedKey_forBlake2b));            
            System.out.println("Shared Key:\t" + Hex.encode(sharedKey) + "\t" + b.encodeToString(sharedKey));
        }
        
        // Data Key: Id not specified, auto-generate a private key on the spot
        // [Or generate s shared key between two randomly generated keys]
        if ((dataKey == null) || (dataKey.length!=32)) {
            dataKey =  X25519.generatePrivateKey();
        }
        if (debug) System.out.println("Data Key:\t" + Hex.encode(dataKey) + "\t" + b.encodeToString(dataKey));
        
        // Generate Encrypted Header and nonce and MAC
        //EncryptedHeader encryptedHeader = new EncryptedHeader(new byte[0], dataKey.getBytes());
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptionType,
                                                              dataKey);
        byte[] encryptedHeaderBytes = encryptedHeader.getEncryptedHeader(sharedKey);
        
        // Get Remaining Length 
        int remainingLength = encryptedHeaderBytes.length + 4 + ownPublicKey.length;
        
        // Generate Header object
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(MagicNumber, 
                                                                    Version,
                                                                    remainingLength,
                                                                    0,
                                                                    ownPublicKey);
        
        // Write Header
        os.write(unencryptedHeader.getHeaderBytes());
        os.write(encryptedHeaderBytes);
        
        //
        // Header is written. Write actual file data
        //
        
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65535];

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
            byte[] encrypted = cipher.encrypt(to_enc, new byte[0]);
            if (debug) {
                byte[] nonce = Arrays.copyOfRange(encrypted, 0, 12);
                System.out.println("Segment Nonce:\t" + Hex.encode(nonce) + "\t" + b.encodeToString(nonce));
            } 
            
            // Write data to output stream
            os.write(encrypted);
        }
        in.close();
        
        os.flush();
        os.close();
    }
    private static void encryptSubranges(Path source, 
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
                                                      GeneralSecurityException,        
                                                      Exception  {        
        // Establish Output Stream
        OutputStream os = Files.newOutputStream(destination);
        if (debug) System.out.println("Writing output to: " + destination);

        // Generate Unencrypted Header
        byte[] ownPublicKey = publicFromPrivate(privateKey);
        
        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey_forBlake2b = getSharedKey(privateKey, publicKey);
        byte[] sharedKey = Blake2B_512(sharedKey_forBlake2b, publicKey, ownPublicKey, debug );
        Base64 b = new Base64();
        if (debug) {
            System.out.println("Own Private Key:\t" + Hex.encode(privateKey) + "\t" + b.encodeToString(privateKey));
            System.out.println("Own Public Key:\t" + Hex.encode(X25519.publicFromPrivate(privateKey)) + "\t" + b.encodeToString(X25519.publicFromPrivate(privateKey)));
            System.out.println("Target Public Key:\t" + Hex.encode(publicKey) + "\t" + b.encodeToString(publicKey));
            System.out.println("Pre Shared Key:\t" + Hex.encode(sharedKey_forBlake2b) + "\t" + b.encodeAsString(sharedKey_forBlake2b));            
            System.out.println("Shared Key:\t" + Hex.encode(sharedKey) + "\t" + b.encodeToString(sharedKey));
        }
        
        // Data Key: Id not specified, auto-generate a private key on the spot
        // [Or generate s shared key between two randomly generated keys]
        if ((dataKey == null) || (dataKey.length!=32)) {
            dataKey =  X25519.generatePrivateKey();
        }
        if (debug) System.out.println("Data Key:\t" + Hex.encode(dataKey) + "\t" + b.encodeToString(dataKey));
        
        // Generate Encrypted Header and nonce and MAC
        //EncryptedHeader encryptedHeader = new EncryptedHeader(new byte[0], dataKey.getBytes());
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptionType,
                                                              dataKey,
                                                              1);
        byte[] encryptedHeaderBytes = encryptedHeader.getEncryptedHeader(sharedKey);
        
        // Get Remaining Length 
        int remainingLength = encryptedHeaderBytes.length + 4 + ownPublicKey.length;
        
        // Generate Header object
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(MagicNumber, 
                                                                    Version,
                                                                    remainingLength,
                                                                    0,
                                                                    ownPublicKey);
        
        // Write Header
        os.write(unencryptedHeader.getHeaderBytes());
        os.write(encryptedHeaderBytes);
        
        //
        // Header is written. Write actual file data
        //
        
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65535];

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
            byte[] encrypted = cipher.encrypt(to_enc, new byte[0]);
            if (debug) {
                byte[] nonce = Arrays.copyOfRange(encrypted, 0, 12);
                System.out.println("Segment Nonce:\t" + Hex.encode(nonce) + "\t" + b.encodeToString(nonce));
            } 
            
            // Range, if range bytes are specified [FIXED.. for testing]
            if (encryptedHeader.getBlockRange() == 1) {
                byte[] random_iv = new byte[16];
                System.arraycopy(encrypted, 0, random_iv, 4, 12);
                byte[] encryptedrange = encrypt(10, 30, (new String(dataKey)), random_iv);
                os.write(encryptedrange);
/*                
                // Sanity Check
                try {
                    byte[] decryoted = decrypt(encryptedrange, (new String(dataKey)), random_iv);
                    int start = getLittleEndian(Arrays.copyOfRange(decryoted, 0, 4));
                    int end = getLittleEndian(Arrays.copyOfRange(decryoted, 4, 8));
                    
                    System.out.println("Sanity Check Range: " + start + "-" + end);
                } catch (Exception ex) {
                    Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
                }
*/
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
        UnencryptedHeader unencryptedHeader = getUnencryptedHeader(in);
        int encryptedHeaderLength = unencryptedHeader.getEncryptedHeaderLength() - 4 - 32; // OK
        
        // Obtain public key from header, unless specified
        if (publicKey==null) {
            publicKey = unencryptedHeader.getPublicKeyBytes();
        }
        Base64 b = new Base64();
        if (debug) System.out.println("Encrypter Public Key:\t" + Hex.encode(publicKey) + "\t" + b.encodeAsString(publicKey));
        
        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey_forBlake2b = getSharedKey(privateKey, publicKey);
        //byte[] sharedKey = Blake2B_512(sharedKey_forBlake2b, publicKey, X25519.publicFromPrivate(privateKey) );
        byte[] sharedKey = Blake2B_512(sharedKey_forBlake2b, X25519.publicFromPrivate(privateKey), publicKey, debug );
        if (debug) {
            System.out.println("My Private Key:\t" + Hex.encode(privateKey) + "\t" + b.encodeAsString(privateKey));
            System.out.println("My Public Key:\t" + Hex.encode(X25519.publicFromPrivate(privateKey)) + "\t" + b.encodeToString(X25519.publicFromPrivate(privateKey)));
            System.out.println("Other Public Key:\t" + Hex.encode(publicKey) + "\t" + b.encodeToString(publicKey));
            System.out.println("Pre Shared Key:\t" + Hex.encode(sharedKey_forBlake2b) + "\t" + b.encodeAsString(sharedKey_forBlake2b));            
            System.out.println("Shared Key:\t" + Hex.encode(sharedKey) + "\t" + b.encodeAsString(sharedKey));            
        }
        
        // Get and Decrypt Header
        byte[] encryptedBytes = new byte[encryptedHeaderLength];
        int read = in.read(encryptedBytes);
        
        // Read unencrypted file Header (decryptes this header with Private GPG Key)
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptedBytes, sharedKey, true);
        
        // New: Range specified?
        int blockRange = encryptedHeader.getBlockRange();
        if (debug) {
            System.out.println("Block Ranges Specified?:\t" + blockRange);
        }        
        //  Create Output Stream
        OutputStream out = Files.newOutputStream(destination);
 
        // Crypt
        TinkConfig.register();
        byte[] dataKey = encryptedHeader.getKey();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Decrypt Loop
        // Encrypt - in 64KiB segments
        int segmentSize = 65535 + 12 + 16;
        if (blockRange == 1) segmentSize += 8; 
        byte[] segment = new byte[segmentSize]; // 64KiB + nonce (12) + mac (16) [ + range (8)]
        
        int start = 0, end = 65535;
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            int rangeDelta = 0;
            if (blockRange == 1) {
                rangeDelta = 8;
                byte[] nonce = Arrays.copyOfRange(segment, 8, 20);
                byte[] iv = new byte[16];
                System.arraycopy(nonce, 0, iv, 4, 12);
                byte[] ranges = Arrays.copyOfRange(segment, 0, 8);
                String key = new String(dataKey);
                byte[] ranges_decrypted = decrypt(ranges, key, iv);
                start = getLittleEndian(Arrays.copyOfRange(ranges_decrypted, 0, 4));
                end = getLittleEndian(Arrays.copyOfRange(ranges_decrypted, 4, 8));                
                //start = getLittleEndian(Arrays.copyOfRange(segment, 0, 4));
                //end = getLittleEndian(Arrays.copyOfRange(segment, 4, 8));                
            }
            if (debug) {
                System.out.println("Block Range: " + start + "-" + end);
            }
            byte[] sub_seg = Arrays.copyOfRange(segment, rangeDelta, seg_len); // -rangeDelta
            if (debug) {
                byte[] nonce = Arrays.copyOfRange(sub_seg, 0, 12);
                System.out.println("Segment Nonce:\t" + Hex.encode(nonce) + "\t" + b.encodeToString(nonce));
            }
            
            // Get next segment
            seg_len = in.read(segment);

            // Decrypt data
            byte[] decrypted = cipher.decrypt(sub_seg, new byte[0]); // should be 64KiB

            // Range
            if (end > decrypted.length) {
                end = decrypted.length;
                if (debug)
                    System.out.println("\tAdjusted Range End: " + end);
            }
            int range = end-start;
            byte[] decrypted_valid = Arrays.copyOfRange(decrypted, start, range);
            
            // Write decryted data to output stream
            out.write(decrypted_valid);
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
/*
    private static void testMeKey() throws UnsupportedEncodingException  {
        String key = "YzRnaC12MQAGYmNyeXB0ABQAAABk5vVvOnQKWJ/jpnQ3aRy3lwARY2hhY2hhMjBfcG9seTEzMDUAPHob63Kmmnf0vI0TYCSGpMIaNEKeEMcqVxb6ZfeDI3737OroVRS0FWh2GyvngMCEq7AGqp2UlT/oCp0sRQ==";
        
        Base64 decoder = new Base64();
        byte[] decode = decoder.decode(key); //.substring(20));
        PrivateKey pk = new PrivateKey(decode, "");

        System.out.println();
    }
*/
    private static void testMeKey() throws UnsupportedEncodingException  {
        String a = "P+kXQCq57aGiJ7qDJTdZxx94xZrlt3EjglXbv8Dm5o8="; // my private
        String b = "Xy8yxfdzDZx1t81PHApVVeF6aoToiRB8BDnf2oWiURk=";
//        String b = "VrgNY5ElJg4iXzNoQ3RgloD8AtFZBT0dPevQ+zVt3HY="; // recipient public
        
        //String a = "pw3/NpM8YmJcpttrPsVYFNnyBmTT6ydErPx3tz7zB60="; // my private
        //String b = "K4oDnIgI+soyYTqYTXvnqP3Yb/JrGgNEF5Ok7JXfpxg="; // recipient public
        
        Base64 c = new Base64();
        try {
            byte[] shared = getSharedKey(c.decode(a), c.decode(b));
            
            String d = c.encodeAsString(shared);
            System.out.println(d);
            
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        String key = "YzRnaC12MQAGYmNyeXB0ABQAAABk5vVvOnQKWJ/jpnQ3aRy3lwARY2hhY2hhMjBfcG9seTEzMDUAPHob63Kmmnf0vI0TYCSGpMIaNEKeEMcqVxb6ZfeDI3737OroVRS0FWh2GyvngMCEq7AGqp2UlT/oCp0sRQ==";
        
        Base64 decoder = new Base64();
        byte[] decode = decoder.decode(key); //.substring(20));
        PrivateKey pk = new PrivateKey(decode, "");

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
