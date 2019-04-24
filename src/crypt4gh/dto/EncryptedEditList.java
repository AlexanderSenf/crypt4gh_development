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
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/**
 *
 * @author asenf
 */
public class EncryptedEditList implements Serializable {
    
    //A list of ranges for data blocks. Data blocks are identified by nonce vakue
    HashMap<String, EditEntry> editList = new HashMap<>();
 
    // Constructoe: Get encrypted bytes, convert into data structure
    public EncryptedEditList(byte[] encryptedBytes, byte[] sharedKey) throws GeneralSecurityException {

        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
        
        // 2. Decrypt
        byte[] plaintext = cipher.decrypt(encryptedBytes, new byte[0]);

        // 3. Assign
        int entries = plaintext.length / 20;
        int position = 0;
        for (int i=0; i<entries; i++) {
            byte[] oneEntryBytes = new byte[20];
            System.arraycopy(plaintext, position, oneEntryBytes, 0, 20);
            position += 20;
            
            EditEntry oneEntry = new EditEntry(oneEntryBytes);
            this.editList.put(Hex.encode(oneEntry.getBlockNonce()), oneEntry);
        }
    }

    public EncryptedEditList() {
        //
    }
    
    /*
     * Getters, Setters
     */
    public void addEntry(EditEntry entry) {
        this.editList.put(Hex.encode(entry.getBlockNonce()), entry);
    }
    
    public EditEntry getEntry(byte[] nocneKey) {
        return this.editList.get(Hex.encode(nocneKey));
    }

    public boolean containsKey(byte[] nonceKey) {
        return this.editList.containsKey(Hex.encode(nonceKey));
    }
    
    // Get bytes for output stream
    public byte[] getEncryptedBytes(byte[] sharedKey) throws GeneralSecurityException {
        // handle empty edit list
        if (this.editList==null || this.editList.size()==0) {
            return (new byte[0]);
        }
        
        // build byte representation of edit list
        int entries = this.editList.size();
        byte[] entryList = new byte[20 * entries];
        Set<String> keySet = this.editList.keySet();
        Iterator<String> iter = keySet.iterator();
        int position = 0;
        while (iter.hasNext()) {
            byte[] temp = (this.editList.get(iter.next())).getBytes(); // nonce|start|end
            System.arraycopy(temp, 0, entryList, position, 20); // position+20
            position += 20;
        }
        
        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
        
        // 2. Enrypt
        byte[] ciphertext = cipher.encrypt(entryList, new byte[0]);
        
        // 3. Return encrypted Header as Byte Array
        return ciphertext;
    }
    
    public void printKeys() {
        Set<String> keySet = this.editList.keySet();
        Iterator<String> iter = keySet.iterator();
        int i = 0;
        while (iter.hasNext()) {
            String next = iter.next();
            System.out.println("Segment Nonce Keys " + i++ + ":\t" + next);        
        }
    }
}
