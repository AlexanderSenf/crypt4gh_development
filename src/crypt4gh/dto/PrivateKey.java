/*
 * Copyright 2019 asenf.
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
package crypt4gh.dto;

import at.favre.lib.crypto.bkdf.KeyDerivationFunction;
import at.favre.lib.crypto.bkdf.Version;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.lambdaworks.crypto.SCrypt;
import com.lambdaworks.crypto.SCryptUtil;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 *
 * @author asenf
 */
public class PrivateKey {
    private byte[]  MAGIC_WORD = new byte[7]; // 'c4gh-v1'
    private String  kdfname; // bcrypt, scrypt
    private int  rounds; // || salt
    private byte[] bSalt = new byte[16];
    private String  ciphername; // chacha20_poly1305
    private byte[] bEncData;
    private String  comment;
    
    private String keyPhrase; 
    
    // generate Key from with given passphrase (using many defaults, for now)
    public PrivateKey(byte[] key, String keyPhrase, String alg) throws GeneralSecurityException, 
                                                                       NoSuchAlgorithmException, 
                                                                       InvalidKeySpecException, 
                                                                       UnsupportedEncodingException {
        // Version 1
        this.MAGIC_WORD = "c4gh-v1".getBytes();
        
        // use bcrypt, for now
        this.kdfname = alg; // bcrypt or scrypt
        
        // set to load factor 7: 128 rounds
        this.rounds = 128;
        
        // Randomly generate salt
        byte[] initSeed = new byte[16];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(initSeed);
        byte[] seed = secureRandom.generateSeed(16);
        this.bSalt = new byte[16];
        secureRandom.nextBytes(this.bSalt);
        
        // chacha20_poly1305
        this.ciphername = "chacha20_poly1305";

        // Generate ChaCha20 key from keyPhrase, via bcrypt kds
        this.keyPhrase = keyPhrase;        
        byte[] pass = getPass();
        
        // Encrypted Key
        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(pass);
        
        // 2. Enrypt
        this.bEncData = cipher.encrypt(key, new byte[0]);
        
        // No Comment, for now
        this.comment = null;
    }
    
    // generate Key from input Array
    public PrivateKey(byte[] input, String keyPhrase) throws UnsupportedEncodingException {
        System.arraycopy(input, 0, this.MAGIC_WORD, 0, 7);

        int iKd_l = getBigEndianShort(Arrays.copyOfRange(input, 7, 9));
        int pos = 9;        
        this.kdfname =  new String(Arrays.copyOfRange(input, pos, pos+iKd_l));
        pos = pos + iKd_l;

        int iR_l = getBigEndianShort(Arrays.copyOfRange(input, pos, pos+2)) - 4; // subtract rounds
        pos = pos + 2;
        this.rounds = getBigEndian(Arrays.copyOfRange(input, pos, pos+4));
        pos = pos + 4;
        System.arraycopy(input, pos, this.bSalt, 0, iR_l);
        pos = pos + iR_l;
        int iCp_l = getBigEndianShort(Arrays.copyOfRange(input, pos, pos+2));
        pos = pos + 2;
        this.ciphername = new String(Arrays.copyOfRange(input, pos, pos+iCp_l));
        pos = pos + iCp_l;
  
        int iEd_l = getBigEndianShort(Arrays.copyOfRange(input, pos, pos+2)); // nonce || cipher
        pos = pos + 2;
        this.bEncData = new byte[iEd_l];
        System.arraycopy(input, pos, this.bEncData, 0, iEd_l);
        pos = pos + iEd_l;
        
        int iC_l = getBigEndianShort(Arrays.copyOfRange(input, pos, pos+2)); 
        pos = pos + 2;
        if (iC_l > 0) {
            this.comment = new String(Arrays.copyOf(input, pos));
        }
        
        this.keyPhrase = keyPhrase;
    }

    // Decrypt and return the private key contained
    public byte[] getKey() throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] key = null;
        
        // Support multiple ciphers
        if (this.ciphername.equalsIgnoreCase("chacha20_poly1305")) {
            // Register Tink
            TinkConfig.register();
            
            // 1. Get Cipher (using bcrypt derived key)
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305(getPass());

            // 2. Decrypt
            byte[] plaintext = cipher.decrypt(this.bEncData, new byte[0]);
            key = new byte[plaintext.length];
            System.arraycopy(plaintext, 0, key, 0, plaintext.length);
        }
                
        return key;
    }
    
    // Generate byte-encoding for Private Key, with length-encoded Strings
    public byte[] getKeyBytes() throws UnsupportedEncodingException {
        // Determine length
        int pkLen = 7   // 'c4gh-v1'
                  + 2 + this.kdfname.length() // Length encoding, crypt name
                  + 2 + 4 + this.bSalt.length // Length encoding, rounds (4), salt (16)
                  + 2 + this.ciphername.length() // Length encoding, 'chacha20_poly1305'
                  + 2 + this.bEncData.length // nonce || keyencrypted || MAC
                  + 2 + (this.comment==null?0:this.comment.length());
        byte[] keyBytes = new byte[pkLen];
        
        int pos = 0;
        System.arraycopy(this.MAGIC_WORD, 0, keyBytes, pos, 7);
        pos = pos + 7;
        
        byte[] bKd_l = shortToBigEndian( (new Integer(this.kdfname.length())).shortValue() );
        System.arraycopy(bKd_l, 0, keyBytes, pos, 2);
        pos = pos + 2;
        byte[] bKd = this.kdfname.getBytes("US-ASCII");
        System.arraycopy(bKd, 0, keyBytes, pos, this.kdfname.length());
        pos = pos + this.kdfname.length();
        
        byte[] bR_l = shortToBigEndian( (new Integer(4 + this.bSalt.length)).shortValue() );
        System.arraycopy(bR_l, 0, keyBytes, pos, 2);
        pos = pos + 2;
        byte[] bRounds = intToBigEndian(this.rounds);
        System.arraycopy(bRounds, 0, keyBytes, pos, bRounds.length);
        pos = pos + bRounds.length;
        System.arraycopy(this.bSalt, 0, keyBytes, pos, this.bSalt.length);
        pos = pos + this.bSalt.length;
        
        byte[] bCp_l = shortToBigEndian( (new Integer(this.ciphername.length())).shortValue() );
        System.arraycopy(bCp_l, 0, keyBytes, pos, 2);
        pos = pos + 2;
        byte[] bCp = this.ciphername.getBytes("US-ASCII");
        System.arraycopy(bCp, 0, keyBytes, pos, this.ciphername.length());
        pos = pos + this.ciphername.length();
        
        byte[] bEd_l = shortToBigEndian( (new Integer(this.bEncData.length)).shortValue() );
        System.arraycopy(bEd_l, 0, keyBytes, pos, 2);
        pos = pos + 2;
        System.arraycopy(this.bEncData, 0, keyBytes, pos, this.bEncData.length);
        pos = pos + this.bEncData.length;

        byte[] bC_l = shortToBigEndian( (new Integer( (this.comment==null?0:this.comment.length()) )).shortValue() );
        System.arraycopy(bC_l, 0, keyBytes, pos, 2);
        pos = pos + 2;
        if (this.comment!=null) {
            byte[] bC = this.comment.getBytes("US-ASCII");
            System.arraycopy(bC, 0, keyBytes, pos, this.comment.length());            
        }
                
        return keyBytes;
    }
    
    private byte[] getPass() throws NoSuchAlgorithmException, 
                                    InvalidKeySpecException, 
                                    UnsupportedEncodingException, 
                                    GeneralSecurityException {
        if (this.kdfname.equalsIgnoreCase("bcrypt")) {
            return getPassBcrypt();
        } else if (this.kdfname.equalsIgnoreCase("scrypt")) {
            return getPassScrypt();
        }
        
        return null;
    }
    // Derive key from input data (bcrypt key derivation function)
    private byte[] getPassBcrypt() throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.DEFAULT_VERSION);        
        int loadFactor = (int) ( Math.log(rounds) / Math.log(2) );
        byte[] pass = kdf.derive(this.bSalt, 
                                 this.keyPhrase.toCharArray(), 
                                 loadFactor, 
                                 null, 
                                 32);
        return pass;
    }
    private byte[] getPassScrypt() throws GeneralSecurityException, UnsupportedEncodingException {
        int N = 65536; // CPU cost parameter. (rounds)
        int r = 16; // Memory cost parameter.
        int p = 1; // Parallelization parameter.
        return SCrypt.scrypt(this.keyPhrase.getBytes("UTF-8"), this.bSalt, this.rounds, r, p, 32);
    }
    
    private int getBigEndianShort(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getShort();
    }
    private int getBigEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getInt();
    }
    
    private byte[] intToBigEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.BIG_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    

    private byte[] shortToBigEndian(short numero) {
            ByteBuffer bb = ByteBuffer.allocate(2);
            bb.order(ByteOrder.BIG_ENDIAN);
            bb.putShort(numero);
            return bb.array();
    }    
    
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
}
