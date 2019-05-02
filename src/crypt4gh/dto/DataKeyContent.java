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

import crypt4gh.dto.interfaces.EncryptedContent;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 *
 * @author asenf
 */
public class DataKeyContent implements Serializable, EncryptedContent {
    
    private byte[] packetType = new byte[4];        // 0
    private byte[] encryptionMethod = new byte[4];
    private byte[] dataEncryptionKey = new byte[32];
    
    public DataKeyContent(int packetType, int encryptionMethod, byte[] dataEncryptionKey) {
        byte[] packetTypeBytes = intToLittleEndian(packetType);
        System.arraycopy(packetTypeBytes, 0, this.packetType, 0, 4);
        
        byte[] encryptionMethodBytes = intToLittleEndian(encryptionMethod);
        System.arraycopy(encryptionMethodBytes, 0, this.encryptionMethod, 0, 4);        
        
        System.arraycopy(dataEncryptionKey, 0, this.dataEncryptionKey, 0, 32);
    }

    public DataKeyContent(byte[] stream) {
        System.arraycopy(stream, 0, this.packetType, 0, 4);
        System.arraycopy(stream, 4, this.encryptionMethod, 0, 4);
        System.arraycopy(stream, 8, this.dataEncryptionKey, 0, 32);
    }
    
    /*
     * Interface Methods
     */
    @Override
    public byte[] getBytes() {
        byte[] result = new byte [4 + 4 + 32];
        
        System.arraycopy(packetType, 0, result, 0, 4);
        System.arraycopy(encryptionMethod, 0, result, 4, 4);
        System.arraycopy(dataEncryptionKey, 0, result, 8, 32);
        
        return result;
    }
        
    @Override
    public int getPacketType() {
        return getLittleEndian(this.packetType);
    }

    public byte[] getDataKey() {
        byte[] key = new byte[32];
        System.arraycopy(this.dataEncryptionKey, 0, key, 0, 32);
        return key;
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

}
