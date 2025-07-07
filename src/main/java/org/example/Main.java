package org.example;

import java.security.PrivateKey;
import java.util.Map;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        PrivateKey rsaPrivateKey = null;
        
        // Ask for debug mode
        System.out.print("Enable debug mode? (y/n): ");
        String enableDebug = scanner.nextLine().trim().toLowerCase();
        boolean debugMode = enableDebug.equals("y") || enableDebug.equals("yes");
        
        // Set debug mode for all classes
        RSADecryption.setDebugMode(debugMode);
        CSVHandler.setDebugMode(debugMode);
        AESDecryption.setDebugMode(debugMode);
        
        System.out.println("Debug mode: " + (debugMode ? "ENABLED" : "DISABLED"));
        
        // Get CSV file path
        System.out.print("Please enter CSV file path: ");
        String csvFilePath = scanner.nextLine().trim();
        
        // Get RSA key path
        System.out.print("Please enter RSA key path: ");
        String rsaKeyPath = scanner.nextLine().trim();
        
        // Get key password
        System.out.print("Please enter key password: ");
        String keyPassword = scanner.nextLine().trim();
        
        // Get key alias
        System.out.print("Please enter key alias: ");
        String keyAlias = scanner.nextLine().trim();
        
        // Display the entered values for verification
        System.out.println("\n--- Input Summary ---");
        System.out.println("CSV File Path: " + csvFilePath);
        System.out.println("RSA Key Path: " + rsaKeyPath);
        System.out.println("Key Password: " + keyPassword);
        System.out.println("Key Alias: " + keyAlias);
        System.out.println("--------------------\n");
        


        //Take header from CSV file
        String[] headers = CSVHandler.getHeaders(csvFilePath);
        if (headers == null) {
            System.out.println("No headers found in CSV");
        } else {
            System.out.println("CSV Headers found: " + java.util.Arrays.toString(headers));
            if (debugMode) {
                System.out.println("--- CSV Data ---\n\n\n");
            }
        }
        //Find headers including "ENCRYPT()"
        System.out.println("Analyzing encrypted headers...");
        if (debugMode) {
            CSVHandler.debugHeaders(csvFilePath);
        }
        
        Map<Integer, String> encryptedHeaders = CSVHandler.getEncryptedHeaders(csvFilePath);
        if (!encryptedHeaders.isEmpty()) {
            System.out.println("Encrypted columns found: " + encryptedHeaders.size());
            for (Map.Entry<Integer, String> entry : encryptedHeaders.entrySet()) {
                System.out.println("  Column " + entry.getKey() + ": Base64 length = " + entry.getValue().length());
            }
        } else {
            System.out.println("No encrypted columns found in CSV");
        }

        //Load RSA private key from PKCS12 keystore
        System.out.println("Loading RSA private key from PKCS12 keystore...");
        if (rsaKeyPath.isEmpty() || keyPassword.isEmpty() || keyAlias.isEmpty()) {
            System.err.println("Error: RSA key path, password, and alias must not be empty.");
            return;
        }
        try {
            rsaPrivateKey = RSADecryption.loadPrivateKeyFromPKCS12(rsaKeyPath, keyPassword, keyAlias);
            if (rsaPrivateKey != null) {
                System.out.println("Private key loaded successfully.");
            } else {
                System.err.println("Failed to load private key.");
                return;
            }
        }
        catch (Exception e) {
            System.err.println("Error loading private key: " + e.getMessage());
            return;
        }
        
        //Decrypt AES key using RSA private key
        //Decrypt AES key using RSA private key from encryptedHeaders
        System.out.println("Decrypting AES keys...");
        Map<Integer, javax.crypto.SecretKey> decryptedAESKeys = new java.util.HashMap<>();
        
        for (Map.Entry<Integer, String> entry : encryptedHeaders.entrySet()) {
            int columnIndex = entry.getKey();
            String encryptedAESKeyBase64 = entry.getValue();
            
            if (debugMode) {
                System.out.println("Decrypting AES key for column " + columnIndex + " (header: " + headers[columnIndex] + ")");
            }
            
            try {
                // Decrypt the AES key using RSA private key
                byte[] decryptedAESKeyBytes = AESDecryption.decryptAESKey(encryptedAESKeyBase64, rsaPrivateKey);
                
                if (decryptedAESKeyBytes != null) {
                    // Convert byte array to AES SecretKey
                    javax.crypto.SecretKey aesKey = AESDecryption.byteArrayToAESKey(decryptedAESKeyBytes);
                    
                    if (aesKey != null) {
                        decryptedAESKeys.put(columnIndex, aesKey);
                        if (debugMode) {
                            System.out.println("AES key decrypted successfully for column " + columnIndex);
                        }
                    } else {
                        System.err.println("Failed to convert decrypted bytes to AES key for column " + columnIndex);
                    }
                } else {
                    System.err.println("Failed to decrypt AES key for column " + columnIndex);
                }
            } catch (Exception e) {
                System.err.println("Error decrypting AES key for column " + columnIndex + ": " + e.getMessage());
            }
        }
        System.out.println("Successfully decrypted " + decryptedAESKeys.size() + " AES keys out of " + encryptedHeaders.size() + " encrypted columns");

        // Create output CSV file with decrypted data
        System.out.println("\nCreating decrypted CSV file...");
        
        // Ask user for output file path
        System.out.print("Please enter output CSV file path (or press Enter for 'decrypted_output.csv'): ");
        String outputFilePath = scanner.nextLine().trim();
        
        if (outputFilePath.isEmpty()) {
            outputFilePath = "decrypted_output.csv"; // Default name
            System.out.println("Using default output file name: " + outputFilePath);
        }
        
        // Create the decrypted CSV file
        boolean success = CSVHandler.createDecryptedCSV(csvFilePath, outputFilePath, decryptedAESKeys);
        
        if (success) {
            System.out.println("✓ Decrypted CSV file created successfully: " + outputFilePath);
            
            // Optional: Also create a version with clean headers
            System.out.print("Do you want to create a version with clean headers (removes ENCRYPT() pattern)? (y/n): ");
            String createCleanHeaders = scanner.nextLine().trim().toLowerCase();
            
            if (createCleanHeaders.equals("y") || createCleanHeaders.equals("yes")) {
                String cleanHeadersFile = outputFilePath.replace(".csv", "_clean_headers.csv");
                boolean cleanSuccess = CSVHandler.createDecryptedCSVWithNewHeaders(csvFilePath, cleanHeadersFile, decryptedAESKeys);
                
                if (cleanSuccess) {
                    System.out.println("✓ Clean headers CSV file created successfully: " + cleanHeadersFile);
                } else {
                    System.err.println("✗ Failed to create clean headers CSV file");
                }
            }
        } else {
            System.err.println("✗ Failed to create decrypted CSV file");
        }
        
        System.out.println("\n--- Process Summary ---");
        System.out.println("Input CSV: " + csvFilePath);
        System.out.println("Output CSV: " + outputFilePath);
        System.out.println("Total columns: " + (headers != null ? headers.length : 0));
        System.out.println("Encrypted columns found: " + encryptedHeaders.size());
        System.out.println("AES keys successfully decrypted: " + decryptedAESKeys.size());
        System.out.println("Decryption process completed successfully!");
        System.out.println("----------------------");
        
        scanner.close();
    }
}
