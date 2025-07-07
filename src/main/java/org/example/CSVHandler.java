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
        //Function to create output CSV with decrypted data and original data for non-encrypted columns
        try (
                FileReader fileReader = new FileReader(inputFile);
                CSVReader csvReader = new CSVReader(fileReader);
                FileWriter fileWriter = new FileWriter(outputFile);
                CSVWriter csvWriter = new CSVWriter(fileWriter)
        ) {
            String[] nextRecord;
            boolean isFirstRow = true;
            
            while ((nextRecord = csvReader.readNext()) != null) {
                String[] outputRecord = new String[nextRecord.length];
                
                // Process each column
                for (int i = 0; i < nextRecord.length; i++) {
                    String cellValue = nextRecord[i];
                    
                    // Check if this column is encrypted and we have a key for it
                    if (decryptedAESKeys.containsKey(i) && !isFirstRow) {
                        // This is an encrypted column and not the header row
                        try {
                            // Split IV and encrypted data
                            InitVector.IVAndData ivAndData = InitVector.splitIVAndEncryptedData(cellValue);
                            
                            if (ivAndData != null) {
                                // Decrypt the field value using the existing function
                                String decryptedValue = AESDecryption.decryptFieldValue(
                                    java.util.Base64.getEncoder().encodeToString(ivAndData.encryptedData),
                                    decryptedAESKeys.get(i), 
                                    ivAndData.iv);
                                
                                outputRecord[i] = decryptedValue != null ? decryptedValue : cellValue;
                            } else {
                                // If IV/data splitting fails, keep original value
                                outputRecord[i] = cellValue;
                            }
                        } catch (Exception e) {
                            logger.log(Level.WARNING, "Error decrypting cell at column " + i + ": " + e.getMessage());
                            outputRecord[i] = cellValue; // Keep original value on error
                        }
                    } else {
                        // Non-encrypted column or header row - keep original value
                        outputRecord[i] = cellValue;
                    }
                }
                
                // Write the processed record to output CSV
                csvWriter.writeNext(outputRecord);
                isFirstRow = false;
            }
            
            csvWriter.flush();
            debugPrint("Decrypted CSV file created successfully: " + outputFile);
            return true;
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error creating decrypted CSV file", e);
            System.err.println("Error creating decrypted CSV file: " + e.getMessage());
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
            String[] nextRecord;
            boolean isFirstRow = true;
            
            while ((nextRecord = csvReader.readNext()) != null) {
                String[] outputRecord = new String[nextRecord.length];
                
                if (isFirstRow) {
                    // Process headers - remove ENCRYPT() pattern
                    for (int i = 0; i < nextRecord.length; i++) {
                        String header = nextRecord[i];
                        if (header != null && header.contains("ENCRYPT(")) {
                            // Remove ENCRYPT(something) pattern from header
                            int encryptIndex = header.indexOf("ENCRYPT(");
                            int endIndex = header.indexOf(")", encryptIndex);
                            if (endIndex != -1) {
                                // Remove the entire ENCRYPT(...) part
                                String cleanHeader = header.substring(0, encryptIndex) + 
                                                   header.substring(endIndex + 1);
                                outputRecord[i] = cleanHeader.trim();
                            } else {
                                outputRecord[i] = header;
                            }
                        } else {
                            outputRecord[i] = header;
                        }
                    }
                } else {
                    // Process data rows
                    for (int i = 0; i < nextRecord.length; i++) {
                        String cellValue = nextRecord[i];
                        
                        // Check if this column is encrypted and we have a key for it
                        if (decryptedAESKeys.containsKey(i)) {
                            try {
                                // Split IV and encrypted data
                                InitVector.IVAndData ivAndData = InitVector.splitIVAndEncryptedData(cellValue);
                                
                                if (ivAndData != null) {
                                    // Decrypt the field value using the existing function
                                    String decryptedValue = AESDecryption.decryptFieldValue(
                                        java.util.Base64.getEncoder().encodeToString(ivAndData.encryptedData),
                                        decryptedAESKeys.get(i), 
                                        ivAndData.iv);
                                    
                                    outputRecord[i] = decryptedValue != null ? decryptedValue : cellValue;
                                } else {
                                    outputRecord[i] = cellValue;
                                }
                            } catch (Exception e) {
                                logger.log(Level.WARNING, "Error decrypting cell at column " + i + ": " + e.getMessage());
                                outputRecord[i] = cellValue;
                            }
                        } else {
                            // Non-encrypted column - keep original value
                            outputRecord[i] = cellValue;
                        }
                    }
                }
                
                // Write the processed record to output CSV
                csvWriter.writeNext(outputRecord);
                isFirstRow = false;
            }
            
            csvWriter.flush();
            debugPrint("Decrypted CSV file with clean headers created successfully: " + outputFile);
            return true;
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error creating decrypted CSV file", e);
            System.err.println("Error creating decrypted CSV file: " + e.getMessage());
            return false;
        }
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

