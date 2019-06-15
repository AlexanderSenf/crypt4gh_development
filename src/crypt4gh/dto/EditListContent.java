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

import crypt4gh.dto.interfaces.EncryptedContent;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 *
 * @author asenf
 */
public class EditListContent implements Serializable, EncryptedContent {

    private byte[] packetType = new byte[4]; // 1
    private byte[] numLengths = new byte[4]; // int
    private byte[] numberList; // long [multiples of 8]
    
    public EditListContent(long[] list) {
        byte[] packetTyeBytes = intToLittleEndian(1);
        System.arraycopy(packetTyeBytes, 0, this.packetType, 0, 4);
        
        byte[] numLengthsBytes = intToLittleEndian(list.length);
        System.arraycopy(numLengthsBytes, 0, this.numLengths, 0, 4);
        
        this.numberList = new byte[8 * list.length];
        int listPosition = 0;
        for (int i=0; i<list.length; i++) {
            byte[] oneValue = longToLittleEndian(list[i]);
            System.arraycopy(oneValue, 0, this.numberList, listPosition, 8);
            listPosition += 8;
        }
    }
    
    public EditListContent(byte[] stream) {
        System.arraycopy(stream, 0, this.packetType, 0, 4);
        System.arraycopy(stream, 4, this.numLengths, 0, 4);
        
        int remaining = stream.length - 4 - 4;
        this.numberList = new byte[remaining];
        System.arraycopy(stream, 8, this.numberList, 0, remaining);
    }
    
    @Override
    public byte[] getBytes() {
        byte[] combined = new byte[4 + 4 + this.numberList.length];
        
        System.arraycopy(this.packetType, 0, combined, 0, 4);
        System.arraycopy(this.numLengths, 0, combined, 4, 4);
        System.arraycopy(this.numberList, 0, combined, 8, this.numberList.length);
        
        return combined;
    }

    @Override
    public int getPacketType() {
        return getLittleEndian(this.packetType);
    }
    
    public long getListNumber(int index) {
        byte[] valueAtIndex = new byte[8];
        System.arraycopy(this.numberList, (index * 8), valueAtIndex, 0, 8);
        return getLittleEndianLong(valueAtIndex);
    }
    
    public long[] getEditList() {
        int numEntries = getLittleEndian(this.numLengths);
        long[] list = new long[numEntries];
        
        for (int i=0; i<numEntries; i++) {
            byte[] valueAtIndex = new byte[8];
            System.arraycopy(this.numberList, (i * 8), valueAtIndex, 0, 8);
            list[i] = getLittleEndianLong(valueAtIndex);
        }
        
        return list;        
    }
    
    /*.encryptionMethod
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private long getLittleEndianLong(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
    }

    private byte[] intToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt((int) numero);
            return bb.array();
    }    
    private byte[] longToLittleEndian(long numero) {
            ByteBuffer bb = ByteBuffer.allocate(8);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(numero);
            return bb.array();
    }    
}
