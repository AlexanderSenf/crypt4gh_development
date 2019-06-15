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

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 *
 * @author asenf
 */
public class Header implements Serializable {
    // Header Structure
    private UnencryptedHeader unencryptedHeader;
    private HeaderPacket[] headerPackets;
    
    // Constants
    private int UNENCRYPTEDHEADERLEN = 16;
    
    /*
     * Allow construction based on data structures (encryption) and a stream of bytes (decryption)
     */
    
    public Header(UnencryptedHeader unencryptedHeader, List<HeaderPacket> headerPackets) {
        this.unencryptedHeader = unencryptedHeader;
        this.headerPackets = new HeaderPacket[headerPackets.size()];
        
        //this.headerPackets = (HeaderPacket[]) headerPackets.toArray();
        
        Iterator<HeaderPacket> iter = headerPackets.iterator();
        int headerPacketCount = 0;
        while (iter.hasNext()) {
            this.headerPackets[headerPacketCount++] = iter.next();
        }
    }
    
    public Header(byte[] stream) {
        // Derive Unencrypted header from input
        byte[] unencryptedHeaderBytes = new byte[UNENCRYPTEDHEADERLEN];
        System.arraycopy(stream, 0, unencryptedHeaderBytes, 0, UNENCRYPTEDHEADERLEN);
        this.unencryptedHeader = new UnencryptedHeader(unencryptedHeaderBytes);
        
        // Number of Header Packets
        int numHeaderPackets = this.unencryptedHeader.getHeaderPacketCount();
        
        // Derive individual Heaader Packets
        int streamPosition = UNENCRYPTEDHEADERLEN; // Start reading after unencrypted header bytes
        for (int i=0; i<numHeaderPackets; i++) {
            // Peek Length
            byte[] headerLengthBytes = Arrays.copyOfRange(stream, streamPosition, 4);
            int headerLength = getLittleEndian(headerLengthBytes);
            
            // construct HeaderPacket from all bytes
            byte[] headerPacketBytes = new byte[headerLength];
            System.arraycopy(stream, streamPosition, headerPacketBytes, 0, headerLength);
            HeaderPacket oneHeaderPacket = new HeaderPacket(headerPacketBytes);
            streamPosition += headerLength;
            
            // Store Header Packet
            this.headerPackets[i] = oneHeaderPacket;
        }
        
    }

    public byte[] getBytes() {
        // Determine Length
        int resultLenght = 0;
        resultLenght += this.unencryptedHeader.getHeaderBytesLength();
        for (int i=0; i<this.headerPackets.length; i++) {
            resultLenght += this.headerPackets[i].getBytesLength();
        }
        
        // Assemble Result
        int position = 0;
        byte[] result = new byte[resultLenght];
        byte[] unencryptedHeaderBytes = this.unencryptedHeader.getHeaderBytes();
        System.arraycopy(unencryptedHeaderBytes, 0, result, position, unencryptedHeaderBytes.length);
        position += unencryptedHeaderBytes.length;
        
        for (int i=0; i<this.unencryptedHeader.getHeaderPacketCount(); i++) {
            byte[] oneHeaderPacket = this.headerPackets[i].getBytes();
            System.arraycopy(oneHeaderPacket, 0, result, position, oneHeaderPacket.length);
            position += oneHeaderPacket.length;
        }
        
        // Return bytes
        return result;
    }
    
    public byte[] getDataKey(byte[] myPrivateKey) throws GeneralSecurityException {
        byte[] dataKey = new byte[32];
        
        for (int i=0; i<this.unencryptedHeader.getHeaderPacketCount(); i++) {
            byte[] key = this.headerPackets[i].getDataKey(myPrivateKey);
            if (key!=null) {
                return key;
            }            
        }
        
        return dataKey;
    }
    
    public long[] getEditList(byte[] myPrivateKey) throws GeneralSecurityException {
        for (int i=0; i<this.unencryptedHeader.getHeaderPacketCount(); i++) {
            long[] list = this.headerPackets[i].getEditList(myPrivateKey);
            if (list!=null) {
                return list;
            }            
        }
        
        return null;
    }
    
    public byte[] getSourcePublicKey() {
        byte[] publicKey = new byte[32];
        
        for (int i=0; i<this.unencryptedHeader.getHeaderPacketCount(); i++) {
            byte[] key = this.headerPackets[i].getSourcePublicKey();
            if (key!=null) {
                return key;
            }            
        }
        
        return publicKey;
    }
    
    /*.encryptionMethod
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
}
