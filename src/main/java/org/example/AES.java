package org.example;

// Java program to demonstrate the creation
// of Encryption and Decryption with Java AES
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;


public class AES {
    public static SecretKey generateKeyAES(int n) throws NoSuchAlgorithmException {
        //generating the AES key with the size of n (128, 192, and 256) bits
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public static GCMParameterSpec generateIvAES() {
        //Generating an IV suitable for AES
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return new GCMParameterSpec(128, iv);
    }

    /**
     * Encrypts the input string using the specified algorithm.
     *
     * @param algorithm the transformation string, e.g., "AES/GCM/NoPadding"
     * @param input the plaintext input to encrypt
     * @param key the AES secret key
     * @param iv the GCM parameter specification (IV)
     * @return the Base64-encoded ciphertext
        byte[] cipherText = cipher.doFinal(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
     * @throws InvalidKeyException if the key is invalid
     * @throws BadPaddingException if padding is incorrect
     * @throws IllegalBlockSizeException if the block size is incorrect
     */
    public static String encryptAES(String algorithm, String input, SecretKey key,
                                    GCMParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        //Function gets bytes of input and returns ciphertext in bytes

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    /**
     * Encrypts the contents of the specified input file using AES and writes the encrypted data to the output file.
     * <p>
     * Note: If the output file already exists, it will be overwritten.
     * </p>
     *
     * @param algorithm the transformation string, e.g., "AES/GCM/NoPadding"
     * @param key the AES secret key
     * @param iv the GCM parameter specification (IV)
     * @param inputFile the file to encrypt
     * @param outputFile the file to write the encrypted data to (will be overwritten if it exists)
     * @throws IOException if an I/O error occurs
     * @throws NoSuchPaddingException if padding mechanism is not available
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid
     * @throws InvalidKeyException if the key is invalid
     * @throws BadPaddingException if padding is incorrect
     * @throws IllegalBlockSizeException if the block size is incorrect
     */
    public static void encryptFileWithAES(String algorithm, SecretKey key, GCMParameterSpec iv,
                                          File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        //AES encryption for a file
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outputStream.write(outputBytes);
            }
        }
    }
}

