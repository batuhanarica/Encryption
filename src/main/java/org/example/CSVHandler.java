package org.example;

import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import com.opencsv.CSVReaderBuilder;

public class CSVHandler {
    private static final Logger logger = Logger.getLogger(CSVHandler.class.getName());
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

    public static void readDataByLine(String file, String delimiter) {
        //Function to read CSV format data line by line
        try (
                FileReader fileReader = new FileReader(file);
                CSVReader csvReader = new CSVReader(fileReader)
        ) {
            String[] nextRecord;

            while ((nextRecord = csvReader.readNext()) != null) {
                for (int i = 0; i < nextRecord.length; i++) {
                    System.out.print(nextRecord[i]);
                    if (i < nextRecord.length - 1) {
                        System.out.print(delimiter);
                    }
                }
                System.out.println();
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error occurs while reading data line by line", e);
        }
    }

    public static String[] getHeaders(String file) {
        //Function to get the headers (first line) of a CSV file as an array
        try (
                FileReader fileReader = new FileReader(file);
                CSVReader csvReader = new CSVReader(fileReader)
        ) {
            String[] headers = csvReader.readNext();
            return headers;
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error occurs while reading CSV headers", e);
            return null;
        }
    }

    public static String[] getColumn(String file, int columnIndex) {
        //Function to get a specific column from the CSV file as an array
        try (
                FileReader fileReader = new FileReader(file);
                CSVReader csvReader = new CSVReader(fileReader)
        ) {
            String[] nextRecord;
            List<String> columnData = new ArrayList<>();

            while ((nextRecord = csvReader.readNext()) != null) {
                if (columnIndex < nextRecord.length) {
                    columnData.add(nextRecord[columnIndex]);
                }
            }
            return columnData.toArray(new String[0]);
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error occurs while reading CSV column", e);
            return null;
        }
    }

    public static Map<Integer, String> getEncryptedHeaders(String file) {
        //Function to find headers with ENCRYPT(something) pattern and return index and content
        Map<Integer, String> encryptedHeaders = new HashMap<>();
        String[] headers = getHeaders(file);
        
        if (headers != null) {
            for (int i = 0; i < headers.length; i++) {
                String header = headers[i];
                if (header != null && header.contains("ENCRYPT(")) {
                    String base64Content = extractBase64FromHeader(header);
                    if (base64Content != null && !base64Content.isEmpty()) {
                        encryptedHeaders.put(i, base64Content);
                    }
                }
            }
        }
        
        return encryptedHeaders;
    }

    public static boolean createDecryptedCSV(String inputFile, String outputFile, 
                                       Map<Integer, javax.crypto.SecretKey> decryptedAESKeys) {
        //Function to create output CSV with decrypted data ONLY for columns with encrypted headers
        try (
                FileReader fileReader = new FileReader(inputFile);
                CSVReader csvReader = new CSVReader(fileReader);
                FileWriter fileWriter = new FileWriter(outputFile);
                CSVWriter csvWriter = new CSVWriter(fileWriter)
        ) {
            debugPrint("=== CSV DECRYPTION PROCESS ===");
            debugPrint("Input file: " + inputFile);
            debugPrint("Output file: " + outputFile);
            debugPrint("AES keys available for columns: " + decryptedAESKeys.keySet());

            String[] nextLine;
            int rowIndex = 0;
            
            while ((nextLine = csvReader.readNext()) != null) {
                String[] processedLine = new String[nextLine.length];
                
                debugPrint("Processing row " + rowIndex + " with " + nextLine.length + " columns");
                
                for (int columnIndex = 0; columnIndex < nextLine.length; columnIndex++) {
                    String originalValue = nextLine[columnIndex];
                    
                    // Check if this column has an AES key (meaning it's encrypted)
                    if (decryptedAESKeys.containsKey(columnIndex)) {
                        debugPrint("Decrypting column " + columnIndex + " in row " + rowIndex);
                        debugPrint("Original encrypted value: " + originalValue);
                        
                        // Skip header row or empty values
                        if (rowIndex == 0 || originalValue == null || originalValue.trim().isEmpty()) {
                            processedLine[columnIndex] = originalValue;
                            debugPrint("Skipping decryption (header row or empty value)");
                        } else {
                            // Get the AES key for this column
                            javax.crypto.SecretKey aesKey = decryptedAESKeys.get(columnIndex);
                            
                            try {
                                // Decrypt the field value using the AES key
                                String decryptedValue = AESDecryption.decryptFieldValueComplete(originalValue, aesKey);
                                
                                if (decryptedValue != null) {
                                    processedLine[columnIndex] = "'" + decryptedValue + "'";
                                    debugPrint("Decryption successful: " + decryptedValue);
                                } else {
                                    // If decryption fails, keep original value
                                    processedLine[columnIndex] = originalValue;
                                    debugPrint("Decryption failed, keeping original value");
                                }
                            } catch (Exception e) {
                                System.err.println("Error decrypting value in row " + rowIndex + ", column " + columnIndex + ": " + e.getMessage());
                                processedLine[columnIndex] = originalValue; // Keep original on error
                            }
                        }
                    } else {
                        // Column is not encrypted, keep original value
                        processedLine[columnIndex] = originalValue;
                    }
                }
                
                // Write the processed line to output CSV
                csvWriter.writeNext(processedLine);
                rowIndex++;
            }
            
            debugPrint("=== CSV DECRYPTION COMPLETE ===");
            debugPrint("Total rows processed: " + rowIndex);
            return true;
            
        } catch (Exception e) {
            System.err.println("Error creating decrypted CSV: " + e.getMessage());
            debugPrint("=== CSV DECRYPTION FAILED ===");
            e.printStackTrace();
            return false;
        }
    }

    public static boolean createDecryptedCSVWithNewHeaders(String inputFile, String outputFile, 
                                                     Map<Integer, javax.crypto.SecretKey> decryptedAESKeys) {
        //Function to create output CSV with decrypted data and clean headers (removes ENCRYPT() pattern)
        try (
                FileReader fileReader = new FileReader(inputFile);
                CSVReader csvReader = new CSVReader(fileReader);
                FileWriter fileWriter = new FileWriter(outputFile);
                CSVWriter csvWriter = new CSVWriter(fileWriter)
        ) {
            debugPrint("=== CSV DECRYPTION WITH CLEAN HEADERS ===");
            debugPrint("Input file: " + inputFile);
            debugPrint("Output file: " + outputFile);

            String[] nextLine;
            int rowIndex = 0;
            
            while ((nextLine = csvReader.readNext()) != null) {
                String[] processedLine = new String[nextLine.length];
                
                for (int columnIndex = 0; columnIndex < nextLine.length; columnIndex++) {
                    String originalValue = nextLine[columnIndex];
                    
                    if (rowIndex == 0) {
                        // Process headers - remove ENCRYPT() pattern
                        if (originalValue != null && originalValue.contains("ENCRYPT(")) {
                            // Extract the column name before ENCRYPT(
                            String cleanHeader = originalValue.substring(0, originalValue.indexOf("ENCRYPT("));
                            // Remove any trailing characters like '(' if present
                            cleanHeader = cleanHeader.replaceAll("\\($", "");
                            processedLine[columnIndex] = cleanHeader.trim();
                            debugPrint("Cleaned header " + columnIndex + ": " + originalValue + " -> " + processedLine[columnIndex]);
                        } else {
                            processedLine[columnIndex] = originalValue;
                        }
                    } else {
                        // Process data rows
                        if (decryptedAESKeys.containsKey(columnIndex)) {
                            debugPrint("Decrypting column " + columnIndex + " in row " + rowIndex);
                            
                            if (originalValue == null || originalValue.trim().isEmpty()) {
                                processedLine[columnIndex] = originalValue;
                            } else {
                                javax.crypto.SecretKey aesKey = decryptedAESKeys.get(columnIndex);
                                
                                try {
                                    String decryptedValue = AESDecryption.decryptFieldValueComplete(originalValue, aesKey);
                                    
                                    if (decryptedValue != null) {
                                        processedLine[columnIndex] = "'" + decryptedValue + "'";
                                        debugPrint("Decryption successful: " + decryptedValue);
                                    } else {
                                        processedLine[columnIndex] = originalValue;
                                        debugPrint("Decryption failed, keeping original value");
                                    }
                                } catch (Exception e) {
                                    System.err.println("Error decrypting value in row " + rowIndex + ", column " + columnIndex + ": " + e.getMessage());
                                    processedLine[columnIndex] = originalValue;
                                }
                            }
                        } else {
                            processedLine[columnIndex] = originalValue;
                        }
                    }
                }
                
                csvWriter.writeNext(processedLine);
                rowIndex++;
            }
            
            debugPrint("=== CSV DECRYPTION WITH CLEAN HEADERS COMPLETE ===");
            return true;
            
        } catch (Exception e) {
            System.err.println("Error creating decrypted CSV with clean headers: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    public static boolean createDecryptedCSVSmart(String inputFile, String outputFile, 
                                            Map<Integer, javax.crypto.SecretKey> decryptedAESKeys) {
        //Function to create output CSV with smart decryption (detects encrypted values automatically)
        try (
                FileReader fileReader = new FileReader(inputFile);
                CSVReader csvReader = new CSVReader(fileReader);
                FileWriter fileWriter = new FileWriter(outputFile);
                CSVWriter csvWriter = new CSVWriter(fileWriter)
        ) {
            debugPrint("=== CSV SMART DECRYPTION PROCESS ===");

            String[] nextLine;
            int rowIndex = 0;
            
            while ((nextLine = csvReader.readNext()) != null) {
                String[] processedLine = new String[nextLine.length];
                
                for (int columnIndex = 0; columnIndex < nextLine.length; columnIndex++) {
                    String originalValue = nextLine[columnIndex];
                    
                    if (rowIndex == 0) {
                        // Header row
                        processedLine[columnIndex] = originalValue;
                    } else if (originalValue != null && !originalValue.trim().isEmpty()) {
                        // Check if this looks like encrypted data (Base64 pattern)
                        String cleanedValue = AESDecryption.cleanFieldValue(originalValue);
                        
                        if (isLikelyEncryptedData(cleanedValue)) {
                            debugPrint("Column " + columnIndex + " appears to contain encrypted data: " + cleanedValue);
                            
                            // Try to decrypt with available keys
                            String decryptedValue = tryDecryptWithAllKeys(cleanedValue, decryptedAESKeys);
                            
                            if (decryptedValue != null) {
                                processedLine[columnIndex] = "'" + decryptedValue + "'";
                                debugPrint("Successfully decrypted: " + decryptedValue);
                            } else {
                                processedLine[columnIndex] = originalValue;
                                debugPrint("Decryption failed, keeping original");
                            }
                        } else {
                            // Doesn't look encrypted, keep original
                            processedLine[columnIndex] = originalValue;
                        }
                    } else {
                        processedLine[columnIndex] = originalValue;
                    }
                }
                
                csvWriter.writeNext(processedLine);
                rowIndex++;
            }
            
            return true;
            
        } catch (Exception e) {
            System.err.println("Error in smart CSV decryption: " + e.getMessage());
            return false;
        }
    }

    private static boolean isLikelyEncryptedData(String value) {
        //Function to detect if a value looks like encrypted Base64 data
        if (value == null || value.length() < 20) {
            return false;
        }
        
        // Check if it's valid Base64 and has reasonable length for encrypted data
        try {
            java.util.Base64.getDecoder().decode(value);
            return value.length() >= 20 && value.matches("^[A-Za-z0-9+/]*={0,2}$");
        } catch (Exception e) {
            return false;
        }
    }

    private static String tryDecryptWithAllKeys(String encryptedValue, Map<Integer, javax.crypto.SecretKey> keys) {
        //Function to try decrypting with all available AES keys
        for (javax.crypto.SecretKey key : keys.values()) {
            try {
                String result = AESDecryption.decryptFieldValueComplete("'" + encryptedValue + "'", key);
                if (result != null && !result.trim().isEmpty()) {
                    return result;
                }
            } catch (Exception e) {
                // Continue trying other keys
            }
        }
        return null;
    }
    
    public static String extractBase64FromHeader(String header) {
        //Function to extract Base64 content from ENCRYPT() pattern in header
        if (header != null && header.contains("ENCRYPT(")) {
            // Find the position of "ENCRYPT("
            int encryptIndex = header.indexOf("ENCRYPT(");
            int startIndex = encryptIndex + 8; // Position after "ENCRYPT("
            
            // Find the closing parenthesis
            int endIndex = header.indexOf(")", startIndex);
            
            if (endIndex != -1) {
                // Extract the Base64 content inside ENCRYPT()
                String base64Content = header.substring(startIndex, endIndex);
                return base64Content.trim();
            }
        }
        return null;
    }
    
    public static void debugHeaders(String file) {
        //Function to debug headers and show what's being extracted
        String[] headers = getHeaders(file);
        if (headers != null) {
            debugPrint("=== HEADER ANALYSIS ===");
            for (int i = 0; i < headers.length; i++) {
                String header = headers[i];
                if (header != null && header.contains("ENCRYPT(")) {
                    debugPrint("Column " + i + ":");
                    debugPrint("  Full header: " + header);
                    
                    String base64Content = extractBase64FromHeader(header);
                    debugPrint("  Extracted Base64: " + base64Content);
                    debugPrint("  Base64 length: " + (base64Content != null ? base64Content.length() : 0));
                    debugPrint("  ---");
                }
            }
            debugPrint("=== END ANALYSIS ===");
        }
    }
}

