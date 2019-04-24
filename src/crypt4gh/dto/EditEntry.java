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

import com.google.crypto.tink.subtle.Hex;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author asenf
 */
public class EditEntry {

    // Size: 20 bytes
    
    // Valid byte range for an encrypted data block
    // Blocks are identified by nonce (this is en entry in a hashset with the 
    // nonce as key)
    private byte[] blockNonce = new byte[12];
    private int start = 0;
    private int end = 65535;
    
    // Provide 
    public EditEntry(int start, int end) {
        this.start = start;
        this.end = end;
    }
    
    public EditEntry(byte[] blockNonce, int start, int end) {
        this(start, end);
        System.arraycopy(blockNonce, 0, this.blockNonce, 0, 12);
    }
    
    public EditEntry(byte[] nonceAndRange) {
        int position = 0;
        System.arraycopy(nonceAndRange, 0, this.blockNonce, 0, 12);
        position += 12;
        
        byte[] sT = new byte[4];
        System.arraycopy(nonceAndRange, position, sT, 0, 4);
        this.start = getLittleEndian(sT);
        position += 4;
        
        byte[] eT = new byte[4];
        System.arraycopy(nonceAndRange, position, eT, 0, 4); // 8
        this.end = getLittleEndian(eT);
    }
    
    /*
     * Getters & Setters
     */
    public void setBlockNonce(byte[] blockNonce) {
        System.arraycopy(blockNonce, 0, this.blockNonce, 0, 12);
    }
    
    public byte[] getBlockNonce() {
        return this.blockNonce;
    }
    
    public void setRange(int start, int end) {
        this.start = start;
        this.end = end;
    }
    
    public int getRangeStart() {
        return this.start;
    }
    
    public int getRangeEnd() {
        return this.end;
    }

    // return byte array version of the entry
    public byte[] getBytes() {
        byte[] result = new byte[20];
        
        System.arraycopy(this.blockNonce, 0, result, 0, 12);
        byte[] sT = intToLittleEndian(this.start);
        System.arraycopy(sT, 0, result, 12, 4); // 16
        byte[] eT = intToLittleEndian(this.end);
        System.arraycopy(eT, 0, result, 16, 4); // 20
        
        return result;
    }
    
    /*
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
    private static byte[] intToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    
}
