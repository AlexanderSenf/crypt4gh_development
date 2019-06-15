/*
 * Copyright 2019 ELIXIR EBI
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
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.X25519;
import static com.google.crypto.tink.subtle.X25519.publicFromPrivate;
import com.rfksystems.blake2b.Blake2b;
import com.rfksystems.blake2b.security.Blake2bProvider;
import crypt4gh.dto.interfaces.EncryptedContent;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author asenf
 * 
 * Encrypt upon Object Creation!
 */
public class HeaderPacket implements Serializable {
    
    private byte[] packetLength = new byte[4];
    private byte[] encryptionMethod = new byte[4];
    private byte[] sourcePublicKey = new byte[32];
    private byte[] encryptedContent;
    
    private boolean debug = false;
    
    public HeaderPacket(byte[] stream) {
        System.arraycopy(stream, 0, this.packetLength, 0, 4);
        System.arraycopy(stream, 4, this.encryptionMethod, 0, 4);
        System.arraycopy(stream, 8, this.sourcePublicKey, 0, 32);
        
        int totalPacketLength = getLittleEndian(this.packetLength);
        int remainingPacketLength = totalPacketLength - 32 - 4 - 4;
        this.encryptedContent = new byte[remainingPacketLength];
        System.arraycopy(stream, 40, this.encryptedContent, 0, remainingPacketLength);
    }
    
    public HeaderPacket(int encryptionMethod, 
                        byte[] sourcePrivateKey, 
                        byte[] targetPublicKey, 
                        EncryptedContent encryptedContent) throws InvalidKeyException, 
                                                                  NoSuchAlgorithmException, 
                                                                  GeneralSecurityException {
        byte[] encryptionMethodBytes = intToLittleEndian(encryptionMethod);
        System.arraycopy(encryptionMethodBytes, 0, this.encryptionMethod, 0, encryptionMethodBytes.length);
        
        byte[] ownPublicKey = publicFromPrivate(sourcePrivateKey);
        System.arraycopy(ownPublicKey, 0, this.sourcePublicKey, 0, ownPublicKey.length);
        
        /*
         * Encrypt the Content Bytes
         */
        byte[] plainContent = encryptedContent.getBytes();

        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey_forBlake2b = getSharedKey(sourcePrivateKey, targetPublicKey);
        byte[] sharedKey = Blake2B_512(sharedKey_forBlake2b, targetPublicKey, ownPublicKey, false );        
        
        Base64 b = new Base64();
        if (debug) {
            System.out.println("(HeaderPacket Encrypt) Source Private:\t" + Hex.encode(sourcePrivateKey) + "\t" + b.encodeToString(sourcePrivateKey));
            System.out.println("(HeaderPacket Encrypt) Source Public:\t" + Hex.encode(ownPublicKey) + "\t" + b.encodeToString(ownPublicKey));
            System.out.println("(HeaderPacket Encrypt) User Public:\t" + Hex.encode(targetPublicKey) + "\t" + b.encodeToString(targetPublicKey));
            System.out.println("(HeaderPacket Encrypt) Shared Key:\t" + Hex.encode(sharedKey) + "\t" + b.encodeToString(sharedKey));
        }

         // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
       
        // Encrypt
        byte[] encrypted = cipher.encrypt(plainContent, new byte[0]);
        this.encryptedContent = new byte[encrypted.length];
        System.arraycopy(encrypted, 0, this.encryptedContent, 0, encrypted.length);
       
        // Calculate length
        int totalLength = 4 + 
                this.encryptionMethod.length + 
                this.sourcePublicKey.length + 
                this.encryptedContent.length;
        
        byte[] packetLengthBytes = intToLittleEndian(totalLength);
        System.arraycopy(packetLengthBytes, 0, this.packetLength, 0, packetLengthBytes.length);        
    }

    public byte[] getBytes() {
        byte[] result = new byte[getBytesLength()];
        
        int position = 0;
        System.arraycopy(this.packetLength, 0, result, position, this.packetLength.length);
        position += this.packetLength.length;
        
        System.arraycopy(this.encryptionMethod, 0, result, position, this.encryptionMethod.length);
        position += this.encryptionMethod.length;

        System.arraycopy(this.sourcePublicKey, 0, result, position, this.sourcePublicKey.length);
        position += this.sourcePublicKey.length;

        System.arraycopy(this.encryptedContent, 0, result, position, this.encryptedContent.length);
        position += this.encryptedContent.length;
        
        
        return result;
    }
    
    public int getBytesLength() {
        int totalLength = 4 + 
                this.encryptionMethod.length + 
                this.sourcePublicKey.length + 
                this.encryptedContent.length;
        
        return totalLength;
    }
    
    public byte[] getDataKey(byte[] myPrivateKey) throws NoSuchAlgorithmException, GeneralSecurityException {
        byte[] key = null;
        EncryptedContent content = getContent(myPrivateKey);
        if (content.getPacketType() == 0) {
            key = ((DataKeyContent)content).getDataKey();
            //return ((DataKeyContent)content).getDataKey();
        } //else {
        //    return null;
        //}
        return key; // last key found
    }
    
    public byte[] getSourcePublicKey() {
        byte[] sourcePublicKey = Arrays.copyOf(this.sourcePublicKey, 32);
        return sourcePublicKey;
    }
    
    public long[] getEditList(byte[] myPrivateKey) throws NoSuchAlgorithmException, GeneralSecurityException {
        long[] list = null;
        EncryptedContent content = getContent(myPrivateKey);
        if (content.getPacketType() == 1) {
            list = ((EditListContent)content).getEditList();
        }
        return list; // last list found
    }
    
    private EncryptedContent getContent(byte[] myPrivateKey) throws InvalidKeyException, NoSuchAlgorithmException, GeneralSecurityException {
        byte[] myPublicKey = publicFromPrivate(myPrivateKey);
                
        byte[] sharedKey_forBlake2b = getSharedKey(myPrivateKey, this.sourcePublicKey);
        byte[] sharedKey = Blake2B_512(sharedKey_forBlake2b, myPublicKey, this.sourcePublicKey, false );        
        
        if (debug) {
            Base64 b = new Base64();
            System.out.println("(HeaderPacket Decrypt) User Private:\t" + Hex.encode(myPrivateKey) + "\t" + b.encodeToString(myPrivateKey));
            System.out.println("(HeaderPacket Decrypt) User Public:\t" + Hex.encode(myPublicKey) + "\t" + b.encodeToString(myPublicKey));
            System.out.println("(HeaderPacket Decrypt) Source Public:\t" + Hex.encode(this.sourcePublicKey) + "\t" + b.encodeToString(this.sourcePublicKey));
            System.out.println("(HeaderPacket Decrypt) Shared Key:\t" + Hex.encode(sharedKey) + "\t" + b.encodeToString(sharedKey));
        }
        
         // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
       
        // Decrypt
        byte[] unencrypted = cipher.decrypt(this.encryptedContent, new byte[0]);
        
        // Crteate correct packet
        byte[] type = Arrays.copyOfRange(unencrypted, 0, 4);
        int packetType = getLittleEndian(type);
        if (packetType==0)
            return new DataKeyContent(unencrypted);
        else if (packetType==1)
            return new EditListContent(unencrypted);
        else
            return null;
    }
    
    /*.encryptionMethod
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
    private byte[] intToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    
    
    private byte[] getSharedKey(byte[] myPrivate, byte[] userPublic) throws InvalidKeyException {
        byte[] computeSharedSecret = X25519.computeSharedSecret(myPrivate, userPublic);
        return computeSharedSecret;
    }

    private byte[] Blake2B_512(byte[] k_sharedKey, 
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

}

