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

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;

import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 *
 * @author asenf
 * 
 * Experimental version, incorporating block ranges for Crypt4GH data blocks
 */
public class EncryptedDataHeader implements Serializable {
    
    public static int getLen() {
        return 36; // encryptionMethod (4) + key (32)
    }
    public static int getEncryptedLen() {
        return 68; // nonce + header + MAC
    }
    
    // Checksum appended to data, at the end of the file
    // 0 = Chacha20-ietf-Poly1305 (Default & only choice; 32 bytes)
    private int encryptionMethod = 0;
    private byte[] key = null;
    
    /*
     * Constructors
     *
     * To add: Check validity of input parameters
     */
    public EncryptedDataHeader(int encryptionMethod, byte[] key) {
        this.encryptionMethod = encryptionMethod;
        switch (encryptionMethod) {
            case 0:
                this.key = new byte[32];
                System.arraycopy(key, 0, this.key, 0, 32);
                break;
        }
    }
    public EncryptedDataHeader(int encryptionMethod, byte[] key, int blockRange) {
        this.encryptionMethod = encryptionMethod;
        switch (encryptionMethod) {
            case 0:
                this.key = new byte[32];
                System.arraycopy(key, 0, this.key, 0, 32);
                break;
        }
    }

    private byte[] getBytes() {
        int headerLength = 4; // 4-byte encryptionType
        
        int keyLength = 0;
        switch (encryptionMethod) {
            case 0:
                keyLength = 32;
                break;
        }
        headerLength += keyLength;
        
        // new field: identify ranges in blocks
        headerLength += 4;

        // Length of encrypted header (in its unencrypted format) is now known
        byte[] concat = new byte[headerLength];
        int position = 0;
        System.arraycopy(intToLittleEndian(this.encryptionMethod), 0, concat, position, 4);
        position += 4;
        System.arraycopy(this.key, 0, concat, position, keyLength);
        
        // Byte array complete
        return concat;
    }
    
    // Expects: Encrypted ByteBuffer --> Automatic Decryption
    public EncryptedDataHeader(byte[] encryptedBytes, byte[] sharedKey, boolean encrypted) throws InvalidKeyException, GeneralSecurityException {

        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
        
        // 2. Decrypt
        byte[] plaintext = cipher.decrypt(encryptedBytes, new byte[0]);

        // 3. Assign
        int position = 0;
        byte[] eT = new byte[4];
        System.arraycopy(plaintext, position, eT, 0, 4);
        this.encryptionMethod = getLittleEndian(eT);
        position += 4;
        
        this.key = new byte[32];
        System.arraycopy(plaintext, position, this.key, 0, 32);
        position += 32;
    }
    
    // Encrypt header with public key, return as byte array
    public byte[] getEncryptedHeader(byte[] sharedKey) throws GeneralSecurityException, IOException {

        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
        
        // 2. Enrypt
        byte[] ciphertext = cipher.encrypt(this.getBytes(), new byte[0]);
        
        // 3. Return encrypted Header as Byte Array
        return ciphertext;
    }

    public int getEncryptionMethod() {
        return this.encryptionMethod;
    }
    
    public byte[] getKey() {
        return this.key;
    }
    
    /*
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
