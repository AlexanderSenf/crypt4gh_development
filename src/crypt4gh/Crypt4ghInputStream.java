/*
 * Copyright 2017 ELIXIR EBI
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
package crypt4gh;

import static crypt4gh.Crypt4gh.MagicNumber;
import static crypt4gh.Crypt4gh.Version;
import crypt4gh.dto.UnencryptedHeader;

import java.io.IOException;
import java.io.InputStream;

import java.nio.ByteBuffer;
import javax.crypto.CipherInputStream;

/**
 *
 * @author asenf
 */
public class Crypt4ghInputStream extends InputStream {

    private CipherInputStream theStream;
    
    public Crypt4ghInputStream(InputStream in, String keyPath, String keyPassphrase) throws Exception {
        // Instantiate Input Stream - if this is a Crypt4gh Input Stream
        // Read unencrypted file Header (validates Magic Number & Version)
        UnencryptedHeader unencryptedHeader = getUnencryptedHeader(in);
        int encryptedHeaderLength = unencryptedHeader.getEncryptedHeaderLength() - 16;
        
        // Read unencrypted file Header (decryptes this header with Private GPG Key)
//        EncryptedHeader encryptedHeader = getEncryptedHeader(in, Paths.get(keyPath), keyPassphrase, encryptedHeaderLength);
        
        // Iterate through Data Blocks
//        for (int i=0; i<encryptedHeader.getNumRecords(); i++) {
//            EncryptionParameters encryptionParameter =  encryptedHeader.getEncryptionParameters(i);

//            AlgorithmParameterSpec paramSpec = new IvParameterSpec(encryptionParameter.getEncryptionParameters().getNonce());
//            Cipher cipher = null;
//            cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
//            SecretKey secret = new SecretKeySpec(encryptionParameter.getEncryptionParameters().getKey(), 0, 32, "AES");
//            cipher.init(Cipher.DECRYPT_MODE, secret, paramSpec);
                        
//            this.theStream = new CipherInputStream(in, cipher);
//        }
    }
    
    @Override
    public int read() throws IOException {
        return this.theStream.read();
    }
    
    @Override
    public int read(byte[] arg0) throws IOException {
        return this.theStream.read(arg0);        
    }

    @Override
    public int read(byte[] arg0, int a, int b) throws IOException {
        return this.theStream.read(arg0, a, b);
    }
    
    @Override
    public long skip(long l) throws IOException {
        return this.theStream.skip(l);
    }

    @Override
    public void close() throws IOException {
        this.theStream.close();
    }
    
    /*
     * Function to read the unencrypted header of an encrypted file
     */
    private UnencryptedHeader getUnencryptedHeader(InputStream source) throws Exception {
        byte[] header = new byte[16];
        source.read(header);

        // Generate Header Object
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(ByteBuffer.wrap(header));
        
        // Validate File Magic Number & Version
        if (!unencryptedHeader.equalsMagicNumber(MagicNumber)) {
            throw new Exception("This is not a CRYPT4GH File.");
        }
        
        // Validate Crypt4GH Version
        if (!unencryptedHeader.equalsVersion(Version)) {
            throw new Exception("Incorrect CRYPT4GH Version.");
        }
        
        return unencryptedHeader;
    }
    
    /*
     * Function to read the encrypted header of an encrypted file
     * Offset is always 16 bytes (length of the unencrypted header)
     * The Header object deals with decryption and encryption
     */
//    private EncryptedHeader getEncryptedHeader(InputStream source, Path keyPath, String keyPassphrase, int headerLength) throws Exception {
//        byte[] header = new byte[headerLength];
//        int read = source.read(header);
//        
//        // Pass encrypted ByteBuffer to Header Object; automatic decryption
//        EncryptedHeader encryptedHeader = new EncryptedHeader(ByteBuffer.wrap(header), keyPath, keyPassphrase);
//        
//        return encryptedHeader;
//    }
}
