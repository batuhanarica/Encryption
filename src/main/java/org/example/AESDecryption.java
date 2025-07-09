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
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
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
            debugPrint("\n");
            
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
    
    public static String cleanFieldValue(String fieldValue) {
        //Function to clean field value by removing quotes and extra characters
        if (fieldValue == null) {
            return null;
        }
        
        // Remove outer double quotes if present
        String cleaned = fieldValue.trim();
        if (cleaned.startsWith("\"") && cleaned.endsWith("\"")) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }
        
        // Remove inner single quotes if present
        if (cleaned.startsWith("'") && cleaned.endsWith("'")) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }
        
        return cleaned.trim();
    }

    public static String decryptFieldValueComplete(String encryptedFieldValue, SecretKey aesKey) {
        //Function to decrypt field value by splitting IV and encrypted data, then decrypting
        try {
            debugPrint("=== FIELD VALUE DECRYPTION ===");
            debugPrint("Original input: " + encryptedFieldValue);
            
            // Clean the field value first
            String cleanedFieldValue = cleanFieldValue(encryptedFieldValue);
            debugPrint("Cleaned input: " + cleanedFieldValue);
            
            if (cleanedFieldValue == null || cleanedFieldValue.isEmpty()) {
                System.err.println("Error: Field value is null or empty after cleaning");
                return null;
            }
            
            debugPrint("Cleaned field value length: " + cleanedFieldValue.length());
            
            // Split IV and encrypted data from the cleaned field value
            InitVector.IVAndData ivAndData = InitVector.splitIVAndEncryptedData(cleanedFieldValue);
            
            if (ivAndData == null) {
                System.err.println("Error: Failed to split IV and encrypted data from field value");
                return null;
            }
            
            debugPrint("IV length: " + ivAndData.iv.length + " bytes");
            debugPrint("Encrypted data length: " + ivAndData.encryptedData.length + " bytes");
            
            // Initialize AES cipher in CFB mode for decryption
            Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(ivAndData.iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            
            // Decrypt the field value
            byte[] decryptedBytes = aesCipher.doFinal(ivAndData.encryptedData);
            
            // Convert decrypted bytes to string
            String decryptedValue = new String(decryptedBytes, "UTF-8");
            
            debugPrint("Decryption successful. Decrypted value length: " + decryptedValue.length());
            debugPrint("Decrypted value: " + decryptedValue);
            debugPrint("=== DECRYPTION COMPLETE ===");
            
            return decryptedValue;
            
        } catch (Exception e) {
            System.err.println("Error decrypting field value: " + e.getMessage());
            debugPrint("=== DECRYPTION FAILED ===");
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptFieldValueWithCustomIV(String encryptedFieldValue, SecretKey aesKey, int ivLength) {
        //Function to decrypt field value with custom IV length
        try {
            debugPrint("=== FIELD VALUE DECRYPTION (Custom IV) ===");
            debugPrint("Original input: " + encryptedFieldValue);
            
            // Clean the field value first
            String cleanedFieldValue = cleanFieldValue(encryptedFieldValue);
            debugPrint("Cleaned input: " + cleanedFieldValue);
            
            if (cleanedFieldValue == null || cleanedFieldValue.isEmpty()) {
                System.err.println("Error: Field value is null or empty after cleaning");
                return null;
            }
            
            debugPrint("Cleaned field value length: " + cleanedFieldValue.length());
            debugPrint("Custom IV length: " + ivLength + " bytes");
            
            // Split IV and encrypted data with custom IV length
            InitVector.IVAndData ivAndData = InitVector.splitIVAndEncryptedData(cleanedFieldValue, ivLength);
            
            if (ivAndData == null) {
                System.err.println("Error: Failed to split IV and encrypted data from field value");
                return null;
            }
            
            debugPrint("IV length: " + ivAndData.iv.length + " bytes");
            debugPrint("Encrypted data length: " + ivAndData.encryptedData.length + " bytes");
            
            // Initialize AES cipher in CFB mode for decryption
            Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(ivAndData.iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            
            // Decrypt the field value
            byte[] decryptedBytes = aesCipher.doFinal(ivAndData.encryptedData);
            
            // Convert decrypted bytes to string
            String decryptedValue = new String(decryptedBytes, "UTF-8");
            
            debugPrint("Decryption successful. Decrypted value length: " + decryptedValue.length());
            debugPrint("Decrypted value: " + decryptedValue);
            debugPrint("=== DECRYPTION COMPLETE ===");
            
            return decryptedValue;
            
        } catch (Exception e) {
            System.err.println("Error decrypting field value: " + e.getMessage());
            debugPrint("=== DECRYPTION FAILED ===");
            e.printStackTrace();
            return null;
        }
    }
}
