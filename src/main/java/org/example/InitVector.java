package org.example;

import java.util.Base64;

public class InitVector {
    
    public static class IVAndData {
        public final byte[] iv;
        public final byte[] encryptedData;
        
        public IVAndData(byte[] iv, byte[] encryptedData) {
            this.iv = iv;
            this.encryptedData = encryptedData;
        }
    }
    
    public static IVAndData splitIVAndEncryptedData(String base64EncodedData, int ivLength) {
        //Function to split initialization vector and encrypted data from Base64 decoded value
        try {
            // Decode the Base64 string
            byte[] decodedData = Base64.getDecoder().decode(base64EncodedData);
            
            // Check if decoded data is long enough to contain IV
            if (decodedData.length < ivLength) {
                System.err.println("Error: Decoded data is too short to contain IV of length " + ivLength);
                return null;
            }
            
            // Extract IV (first ivLength bytes)
            byte[] iv = new byte[ivLength];
            System.arraycopy(decodedData, 0, iv, 0, ivLength);
            
            // Extract encrypted data (remaining bytes)
            byte[] encryptedData = new byte[decodedData.length - ivLength];
            System.arraycopy(decodedData, ivLength, encryptedData, 0, encryptedData.length);
            
            return new IVAndData(iv, encryptedData);
        } catch (Exception e) {
            System.err.println("Error splitting IV and encrypted data: " + e.getMessage());
            return null;
        }
    }
    
    public static IVAndData splitIVAndEncryptedData(String base64EncodedData) {
        //Function to split IV and encrypted data using default AES block size (16 bytes)
        return splitIVAndEncryptedData(base64EncodedData, 16);
    }

    
}
