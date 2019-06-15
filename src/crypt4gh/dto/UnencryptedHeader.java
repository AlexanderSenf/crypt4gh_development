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
package crypt4gh.dto;

import java.io.Serializable;
import java.nio.ByteBuffer;
//import java.nio.ByteOrder;
import java.util.Arrays;
//import java.util.Base64;

/**
 *
 * @author asenf
 */
public class UnencryptedHeader implements Serializable {
    private byte[] magicNumber = new byte[8];           // 'crypt4gh'
    private byte[] version = new byte[4];               // 1 (Correspond to Spec Version)
    private byte[] headerPacketCount = new byte[4];     // How many header packets to read
    
    public static int UNENCRYPTEDHEADERLENGTH = 16;
    
    // Instantiate header fields from byte array
    public UnencryptedHeader(byte[] bytes) {
        magicNumber = Arrays.copyOfRange(bytes, 0, 8);
        version = Arrays.copyOfRange(bytes, 8, 12);
        headerPacketCount = Arrays.copyOfRange(bytes, 12, 16);
    }
    
    // Instantiate header by providing values
    public UnencryptedHeader(byte[] magicNumber, 
                             byte[] version,
                             byte[] headerPacketCount) {
        this.magicNumber = Arrays.copyOf(magicNumber, 8);
        this.version = Arrays.copyOf(version, 4);
        this.headerPacketCount = Arrays.copyOf(headerPacketCount, 4);
    }

    public UnencryptedHeader(byte[] magicNumber, 
                             byte[] version, 
                             int headerPacketCount) {
        this.magicNumber = Arrays.copyOf(magicNumber, 8);
        this.version = Arrays.copyOf(version, 4);
        ByteBuffer dbuf1 = ByteBuffer.allocate(4);        
        dbuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(headerPacketCount);
        this.headerPacketCount = dbuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN).array();
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
    public int getHeaderPacketCount() {
        return getLittleEndian(headerPacketCount);
    }
    
    // Get byte array version of header
    public byte[] getHeaderBytes() {
        byte[] concatenated = new byte[UNENCRYPTEDHEADERLENGTH];
        
        System.arraycopy(this.magicNumber, 0, concatenated, 0, 8);
        System.arraycopy(this.version, 0, concatenated, 8, 4);
        System.arraycopy(this.headerPacketCount, 0, concatenated, 12, 4);
        
        return concatenated;
    }
    
    public int getHeaderBytesLength() {
        return UNENCRYPTEDHEADERLENGTH;
    }
    
    public void print() {
        System.out.println("magicNumber: " + new String(magicNumber));
        System.out.println("version: " + new String(version) + "  " + getLittleEndian(version));
        System.out.println("headerPacketCount: " + new String(headerPacketCount) + "  " + getLittleEndian(headerPacketCount));
    }
    
    /*.encryptionMethod
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
/*    
    private int getBigEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getInt();
    }

    private byte[] intToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    
*/
}
