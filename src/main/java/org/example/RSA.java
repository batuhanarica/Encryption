package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;

public class RSA{
    private static PublicKey publicKey;
    private static PrivateKey privateKey;

    public static void generateKeyRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

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
