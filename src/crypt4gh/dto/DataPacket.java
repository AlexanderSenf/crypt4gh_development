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
import java.security.GeneralSecurityException;

/**
 *
 * @author asenf
 */
public class DataPacket {

    int DATAPACKETLENGTH = 12 + 65536 + 16;
    
    byte[] encryptedBytes;
    
    public DataPacket(byte[] stream) {
        int streamLength = stream.length>DATAPACKETLENGTH?DATAPACKETLENGTH:stream.length;
        this.encryptedBytes = new byte[streamLength];
        System.arraycopy(stream, 0, this.encryptedBytes, 0, streamLength);
    }
    
    public DataPacket(byte[] stream, byte[] dataKey) throws GeneralSecurityException {
        
         // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Encrypt
        byte[] encrypted = cipher.encrypt(stream, new byte[0]);
        this.encryptedBytes = new byte[encrypted.length];
        System.arraycopy(encrypted, 0, this.encryptedBytes, 0, encrypted.length);
    }
    
    public byte[] getBytes() {
        byte[] result = new byte[this.encryptedBytes.length];
        System.arraycopy(this.encryptedBytes, 0, result, 0, this.encryptedBytes.length);
        return result;
    }
    
}
