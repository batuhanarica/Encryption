package org.example;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;

public class RSADecryption {

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


    public static PrivateKey loadPrivateKeyFromPKCS12(String pkcs12FilePath, String password, String alias) {
        //Function to load private key from PKCS12 file with detailed debugging
        try {
            debugPrint("=== PKCS12 KEY LOADING DEBUG ===");
            debugPrint("PKCS12 file path: " + pkcs12FilePath);
            debugPrint("Requested alias: " + alias);
            
            // Load PKCS12 keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(pkcs12FilePath)) {
                keyStore.load(fis, password.toCharArray());
            }
            
            // List all aliases in the keystore
            debugPrint("Available aliases in PKCS12 file:");
            Enumeration<String> aliases = keyStore.aliases();
            int aliasCount = 0;
            while (aliases.hasMoreElements()) {
                String availableAlias = aliases.nextElement();
                aliasCount++;
                debugPrint("  " + aliasCount + ". " + availableAlias);
                
                // Check if this alias has a private key
                if (keyStore.isKeyEntry(availableAlias)) {
                    debugPrint("     -> Has private key: YES");
                    Key key = keyStore.getKey(availableAlias, password.toCharArray());
                    debugPrint("     -> Key type: " + key.getClass().getSimpleName());
                    debugPrint("     -> Algorithm: " + key.getAlgorithm());
                    
                    if (key instanceof java.security.interfaces.RSAPrivateKey) {
                        java.security.interfaces.RSAPrivateKey rsaKey = (java.security.interfaces.RSAPrivateKey) key;
                        debugPrint("     -> RSA key size: " + rsaKey.getModulus().bitLength() + " bits");
                    }
                } else {
                    debugPrint("     -> Has private key: NO");
                }
                
                // Check if this alias has a certificate
                if (keyStore.isCertificateEntry(availableAlias)) {
                    debugPrint("     -> Has certificate: YES");
                } else {
                    debugPrint("     -> Has certificate: NO");
                }
            }
            
            debugPrint("Total aliases found: " + aliasCount);
            
            // Try to get the requested key
            if (keyStore.containsAlias(alias)) {
                debugPrint("Requested alias '" + alias + "' found in keystore");
                
                if (keyStore.isKeyEntry(alias)) {
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
                    debugPrint("Private key loaded successfully");
                    debugPrint("Key algorithm: " + privateKey.getAlgorithm());
                    debugPrint("Key format: " + privateKey.getFormat());
                    
                    if (privateKey instanceof java.security.interfaces.RSAPrivateKey) {
                        java.security.interfaces.RSAPrivateKey rsaKey = (java.security.interfaces.RSAPrivateKey) privateKey;
                        debugPrint("RSA key modulus length: " + rsaKey.getModulus().bitLength() + " bits");
                    }
                    
                    debugPrint("=== PKCS12 LOADING SUCCESS ===");
                    return privateKey;
                } else {
                    System.err.println("Alias '" + alias + "' does not contain a private key");
                }
            } else {
                System.err.println("Alias '" + alias + "' not found in keystore");
                System.err.println("Available aliases: " + java.util.Collections.list(keyStore.aliases()));
            }
            
        } catch (Exception e) {
            System.err.println("=== PKCS12 LOADING ERROR ===");
            System.err.println("Error loading private key from PKCS12: " + e.getMessage());
            e.printStackTrace();
        }
        
        return null;
    }
}
