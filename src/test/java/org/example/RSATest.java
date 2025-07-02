package org.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.security.NoSuchAlgorithmException;

class RSATest {

    @Test
    @DisplayName("Test RSA Key Pair Generation")
    void testGenerateKeyRSA() {
        assertDoesNotThrow(() -> {
            RSA.generateKeyRSA();
        }, "Key generation should not throw an exception");
    }

    @Test
    @DisplayName("Test RSA Encryption with Generated Key")
    void testEncryptRSAWithGeneratedKey() throws Exception {
        RSA.generateKeyRSA();
        String plaintext = "Hello, RSA!";
        String encrypted = RSA.encryptRSA(plaintext);
        assertNotNull(encrypted, "Encrypted text should not be null");
        assertNotEquals(plaintext, encrypted, "Encrypted text should differ from plaintext");
    }

    @Test
    @DisplayName("Test RSA Encryption Without Prior Key Generation")
    void testEncryptRSAWithoutKeyGeneration() throws Exception {
        // This should trigger key generation inside encryptRSA
        String plaintext = "Test without explicit key generation";
        String encrypted = RSA.encryptRSA(plaintext);
        assertNotNull(encrypted, "Encrypted text should not be null");
        assertNotEquals(plaintext, encrypted, "Encrypted text should differ from plaintext");
    }
}