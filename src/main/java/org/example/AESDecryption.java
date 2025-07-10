package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

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

    
    public static boolean isEnclosedInQuotes(String value) {
        //Function to check if value is enclosed in single quotes
        if (value == null || value.length() < 2) {
            return false;
        }
        
        String trimmed = value.trim();
        
        // Check for double quotes containing single quotes: "'value'"
        if (trimmed.startsWith("\"'") && trimmed.endsWith("'\"")) {
            return true;
        }
        
        // Check for direct single quotes: 'value'
        if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
            return true;
        }
        
        return false;
    }

    public static String extractValueFromQuotes(String quotedValue) {
        //Function to extract the actual value from between quotes
        if (quotedValue == null) {
            return null;
        }
        
        String trimmed = quotedValue.trim();
        
        // Handle double quotes containing single quotes: "'value'" -> value
        if (trimmed.startsWith("\"'") && trimmed.endsWith("'\"")) {
            return trimmed.substring(2, trimmed.length() - 2);
        }
        
        // Handle direct single quotes: 'value' -> value
        if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        
        return trimmed;
    }

    public static boolean looksLikeEncryptedData(String value) {
        //Function to determine if a value looks like encrypted Base64 data
        if (value == null || value.length() < 16) {
            return false;
        }
        
        // Check if it's valid Base64 format
        try {
            Base64.getDecoder().decode(value);
            
            // Additional checks for encrypted data characteristics
            // Encrypted data is usually longer and contains mix of characters
            boolean hasUpperCase = value.matches(".*[A-Z].*");
            boolean hasLowerCase = value.matches(".*[a-z].*");
            boolean hasNumbers = value.matches(".*[0-9].*");
            boolean hasBase64Chars = value.matches(".*[+/].*");
            
            // If it has Base64 characteristics and reasonable length, consider it encrypted
            return value.length() >= 16 && (hasUpperCase || hasLowerCase) && 
                   (hasNumbers || hasBase64Chars);
            
        } catch (Exception e) {
            return false;
        }
    }

    public static String tryDecryptQuotedValue(String quotedValue, Map<Integer, SecretKey> availableKeys) {
        //Function to try decrypting a quoted value with all available AES keys
        if (!isEnclosedInQuotes(quotedValue)) {
            return quotedValue; // Not quoted, return as-is
        }
        
        // Extract the value from quotes
        String extractedValue = extractValueFromQuotes(quotedValue);
        
        // Check if it looks like encrypted data
        if (!looksLikeEncryptedData(extractedValue)) {
            return quotedValue; // Doesn't look encrypted, return original
        }
        
        debugPrint("=== TRYING TO DECRYPT QUOTED VALUE ===");
        debugPrint("Original quoted value: " + quotedValue);
        debugPrint("Extracted value: " + extractedValue);
        
        // Try each available AES key
        for (Map.Entry<Integer, SecretKey> keyEntry : availableKeys.entrySet()) {
            SecretKey aesKey = keyEntry.getValue();
            debugPrint("Trying AES key from column " + keyEntry.getKey());
            
            try {
                String decryptedValue = decryptFieldValueComplete("'" + extractedValue + "'", aesKey);
                
                if (decryptedValue != null && !decryptedValue.trim().isEmpty()) {
                    debugPrint("SUCCESS: Decrypted with key from column " + keyEntry.getKey());
                    debugPrint("Decrypted value: " + decryptedValue);
                    return "'" + decryptedValue + "'"; // Return in quotes format
                }
            } catch (Exception e) {
                debugPrint("Failed with key from column " + keyEntry.getKey() + ": " + e.getMessage());
            }
        }
        
        debugPrint("All decryption attempts failed, returning original value");
        return quotedValue; // Return original if all attempts fail
    }
}
