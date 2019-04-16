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
package crypt4gh.dto;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 * @author asenf
 */
public class UnencryptedHeader implements Serializable {
    private byte[] magicNumber = new byte[8];           // 'crypt4gh'
    private byte[] version = new byte[4];               // 1
    private byte[] encryptedHeaderLength = new byte[4]; // length of the remaining header (inc 28 byte nonce+MAC)
    private int headerMethod;                           // 0
    private byte[] publicKey = new byte[32];             // {public key bytes}
    
    // Instantiate header fields from byte array
    public UnencryptedHeader(byte[] bytes) {
        magicNumber = Arrays.copyOfRange(bytes, 0, 8);
        version = Arrays.copyOfRange(bytes, 8, 12);
        encryptedHeaderLength = Arrays.copyOfRange(bytes, 12, 16);
        int len = getLittleEndian(encryptedHeaderLength);        
        byte[] hT = new byte[4];
        System.arraycopy(bytes, 16, hT, 0, 4);
        headerMethod = getLittleEndian(hT);
        publicKey = Arrays.copyOfRange(bytes, 20, 52);
    }
    
    // Instantiate header by providing values
    public UnencryptedHeader(byte[] magicNumber, 
                             byte[] version,
                             byte[] encryptedHeaderLength,
                             int headerMethod,
                             byte[] publicKey) {
        this.magicNumber = Arrays.copyOf(magicNumber, 8);
        this.version = Arrays.copyOf(version, 4);
        this.encryptedHeaderLength = Arrays.copyOf(encryptedHeaderLength, 4);
        this.headerMethod = headerMethod;
        this.publicKey = Arrays.copyOf(publicKey, 32);
    }

    public UnencryptedHeader(byte[] magicNumber, 
                             byte[] version, 
                             int encryptedHeaderLength,
                             int headerMethod,
                             byte[] public_key) {
        this.magicNumber = Arrays.copyOf(magicNumber, 8);
        this.version = Arrays.copyOf(version, 4);
        ByteBuffer dbuf1 = ByteBuffer.allocate(4);        
        dbuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(encryptedHeaderLength);
        this.encryptedHeaderLength = dbuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN).array();        
        this.headerMethod = headerMethod;
        this.publicKey = Arrays.copyOf(public_key, 32);
    }

    public UnencryptedHeader(ByteBuffer bb) {
        this(bb.array());
    }

    public Boolean equalsMagicNumber(byte[] magicNumber) {
        return Arrays.equals(magicNumber, this.magicNumber);
    }

    // Compare version byte arrays
    public Boolean equalsVersion(byte[] version) {
        return Arrays.equals(version, this.version);
    }
    
    // Get Version as Integer
    public int getVersion() {
        return getLittleEndian(version);
    }

    // Get lenght of encrypted header as Integer
    public int getEncryptedHeaderLength() {
        return getLittleEndian(encryptedHeaderLength);
    }
    
    // Get Header Method
    public int getHeaderMethod() {
        return this.headerMethod;
    }
    
    // Get Public Key as String
    public byte[] getPublicKeyBytes() {
        return this.publicKey;
    }

    // Get byte array version of header
    public byte[] getHeaderBytes() {
        //int len = getLittleEndian(this.encryptedHeaderLength);
        //int headerLen = 21 + len;
        int headerLen = 52;
        byte[] concatenated = new byte[headerLen];
        
        System.arraycopy(this.magicNumber, 0, concatenated, 0, 8);
        System.arraycopy(this.version, 0, concatenated, 8, 4);
        System.arraycopy(this.encryptedHeaderLength, 0, concatenated, 12, 4);
        System.arraycopy(intToLittleEndian(this.headerMethod), 0, concatenated, 16, 4);
        System.arraycopy(this.publicKey, 0, concatenated, 20, 32);
        
        return concatenated;
    }
    
    public void print() {
        System.out.println("magicNumber: " + new String(magicNumber));
        System.out.println("version: " + new String(version));
        System.out.println("encryptedHeaderLength: " + new String(encryptedHeaderLength));
        System.out.println("headerMethod: " + headerMethod);
        System.out.println("publicKey: " + new String(publicKey));
        String encodedString = Base64.getEncoder().encodeToString(publicKey);
        System.out.println("publicKey Base64: " + encodedString);
    }
    
    /*.encryptionMethod
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
    private int getBigEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getInt();
    }

    private static byte[] intToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    
}
