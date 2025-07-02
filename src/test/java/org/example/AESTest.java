package org.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import javax.crypto.spec.SecretKeySpec;

class AESTest {

    @Test
    void testGenerateKeyAES() throws NoSuchAlgorithmException {
        SecretKey key128 = AES.generateKeyAES(128);
        assertNotNull(key128);
        assertEquals("AES", key128.getAlgorithm());
        assertEquals(16, key128.getEncoded().length);

        SecretKey key192 = AES.generateKeyAES(192);
        assertNotNull(key192);
        assertEquals(24, key192.getEncoded().length);

        SecretKey key256 = AES.generateKeyAES(256);
        assertNotNull(key256);
        assertEquals(32, key256.getEncoded().length);
    }

    @Test
    void testGenerateIvAES() {
        GCMParameterSpec iv = AES.generateIvAES();
        assertNotNull(iv);
        // GCMParameterSpec should have 12 bytes IV
        assertEquals(12, iv.getIV().length);
        assertEquals(128, iv.getTLen());
    }

    @Test
    void testEncryptAESAndDecrypt() throws Exception {
        String algorithm = "AES/GCM/NoPadding";
        String input = "Hello, AES!";
        SecretKey key = AES.generateKeyAES(128);
        GCMParameterSpec iv = AES.generateIvAES();

        String cipherText = AES.encryptAES(algorithm, input, key, iv);
        assertNotNull(cipherText);
        assertNotEquals(input, cipherText);

        // Decrypt to verify correctness
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainBytes = cipher.doFinal(java.util.Base64.getDecoder().decode(cipherText));
        String decrypted = new String(plainBytes);
        assertEquals(input, decrypted);
    }

    @Test
    void testEncryptFileWithAES() throws Exception {
        String algorithm = "AES/GCM/NoPadding";
        SecretKey key = AES.generateKeyAES(128);
        GCMParameterSpec iv = AES.generateIvAES();

        File inputFile = File.createTempFile("aes_test_input", ".txt");
        File outputFile = File.createTempFile("aes_test_output", ".enc");
        File decryptedFile = File.createTempFile("aes_test_decrypted", ".txt");

        try {
            String content = "File encryption test content!";
            Files.write(inputFile.toPath(), content.getBytes());

            AES.encryptFileWithAES(algorithm, key, iv, inputFile, outputFile);

            assertTrue(outputFile.length() > 0);
            assertNotEquals(Files.readAllBytes(inputFile.toPath()), Files.readAllBytes(outputFile.toPath()));

            // Decrypt the file to verify correctness
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            try (FileInputStream fis = new FileInputStream(outputFile);
                 FileOutputStream fos = new FileOutputStream(decryptedFile)) {
                byte[] buffer = new byte[64];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    if (output != null) {
                        fos.write(output);
                    }
                }
                byte[] outputBytes = cipher.doFinal();
                if (outputBytes != null) {
                    fos.write(outputBytes);
                }
            }
            String decryptedContent = new String(Files.readAllBytes(decryptedFile.toPath()));
            assertEquals(content, decryptedContent);
        } finally {
            inputFile.delete();
            outputFile.delete();
            decryptedFile.delete();
        }
    }
}
