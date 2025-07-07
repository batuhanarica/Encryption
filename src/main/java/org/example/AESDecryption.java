package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.io.FileInputStream;

public class AESDecryption {
    
    private static boolean debugMode = false;

    public static void setDebugMode(boolean enabled) {
        debugMode = enabled;
    }

    public static boolean isDebugMode() {
        return debugMode;
    }

    private static void debugPrint(String message) {
        if (debugMode) {
            System.out.println(message);
        }
    }
    
    public static byte[] decryptAESKey(String encryptedAESKey, PrivateKey rsaPrivateKey) {
        //Function to decrypt AES key using RSA private key
        try {
            // Debug logging
            debugPrint("=== AES KEY DECRYPTION DEBUG ===");
            debugPrint("Input Base64 string length: " + encryptedAESKey.length());
            debugPrint("Input Base64 string (first 100 chars): " + 
                encryptedAESKey.substring(0, Math.min(100, encryptedAESKey.length())));
            debugPrint("Input Base64 string (last 50 chars): " + 
                encryptedAESKey.substring(Math.max(0, encryptedAESKey.length() - 50)));
            
            // Initialize RSA cipher for decryption
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            
            // Decode the Base64 encoded encrypted AES key
            byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedAESKey);
            debugPrint("Decoded byte array length: " + encryptedKeyBytes.length);
            
            // Check RSA key size
            if (rsaPrivateKey instanceof java.security.interfaces.RSAPrivateKey) {
                java.security.interfaces.RSAPrivateKey rsaKey = (java.security.interfaces.RSAPrivateKey) rsaPrivateKey;
                int keySize = rsaKey.getModulus().bitLength();
                debugPrint("RSA key size: " + keySize + " bits");
                debugPrint("Expected max encrypted block size: " + (keySize / 8) + " bytes");
            }
            
            // Decrypt the AES key
            byte[] decryptedAESKey = rsaCipher.doFinal(encryptedKeyBytes);
            debugPrint("Decrypted AES key length: " + decryptedAESKey.length + " bytes");
            debugPrint("=== DECRYPTION SUCCESS ===");
            
            return decryptedAESKey;
        } catch (Exception e) {
            System.err.println("=== DECRYPTION ERROR ===");
            System.err.println("Error type: " + e.getClass().getSimpleName());
            System.err.println("Error message: " + e.getMessage());
            System.err.println("========================");
            return null;
        }
    }
    
    public static SecretKey byteArrayToAESKey(byte[] keyBytes) {
        //Function to convert byte array to AES SecretKey
        try {
            if (keyBytes == null || keyBytes.length == 0) {
                System.err.println("Error: Key bytes cannot be null or empty");
                return null;
            }
            
            // Create AES SecretKey from byte array
            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
            return aesKey;
        } catch (Exception e) {
            System.err.println("Error creating AES key from bytes: " + e.getMessage());
            return null;
        }
    }
    
    public static String decryptFieldValue(String encryptedFieldValue, SecretKey aesKey, byte[] iv) {
        //Function to decrypt field value using AES key and initialization vector (CFB mode)
        try {
            // Initialize AES cipher in CFB mode for decryption
            Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            
            // Decode the Base64 encoded encrypted field value
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedFieldValue);
            
            // Decrypt the field value
            byte[] decryptedBytes = aesCipher.doFinal(encryptedBytes);
            
            // Convert decrypted bytes to string
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            System.err.println("Error decrypting field value: " + e.getMessage());
            return null;
        }
    }
}
