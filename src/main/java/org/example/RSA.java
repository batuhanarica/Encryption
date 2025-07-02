package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;

public class RSA{
    private static PublicKey publicKey;
    private static PrivateKey privateKey;

    /**
     * Generates a new RSA key pair with a key size of 2048 bits and assigns the generated
     * private and public keys to the corresponding class fields.
     *
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available in the environment.
     */
    public static void generateKeyRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    /**
     * Encrypts the given plaintext string using the RSA algorithm and the public key.
     * If the public key is not initialized, it generates a new RSA key pair.
     *
     * @param plaintext the plain text string to be encrypted
     * @return the encrypted text, encoded in Base64 format
     * @throws Exception if an error occurs during encryption or key generation
     */
    public static String encryptRSA(String plaintext) throws Exception {
        if (publicKey == null) {
            RSA.generateKeyRSA();  // Ensure keys are generated
        }

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = encryptCipher.doFinal(plaintext.getBytes());
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Encrypted: " + encryptedText);
        return encryptedText;
    }

}
