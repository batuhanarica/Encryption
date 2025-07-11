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
        //Function to create output CSV with decrypted data for ALL quoted values
        try (
                FileReader fileReader = new FileReader(inputFile);
                CSVReader csvReader = new CSVReader(fileReader);
                FileWriter fileWriter = new FileWriter(outputFile);
                CSVWriter csvWriter = new CSVWriter(fileWriter)
        ) {
            debugPrint("=== CSV DECRYPTION PROCESS (ALL QUOTED VALUES) ===");
            debugPrint("Input file: " + inputFile);
            debugPrint("Output file: " + outputFile);
            debugPrint("AES keys available: " + decryptedAESKeys.size());

            String[] nextLine;
            int rowIndex = 0;
            
            while ((nextLine = csvReader.readNext()) != null) {
                String[] processedLine = new String[nextLine.length];
                
                debugPrint("Processing row " + rowIndex + " with " + nextLine.length + " columns");
                
                for (int columnIndex = 0; columnIndex < nextLine.length; columnIndex++) {
                    String originalValue = nextLine[columnIndex];
                    
                    // For header row (row 0), keep the original header
                    if (rowIndex == 0) {
                        processedLine[columnIndex] = originalValue;
                        debugPrint("Header row - keeping original: " + originalValue);
                    } 
                    // For data rows, check if value is quoted and try to decrypt
                    else {
                        debugPrint("Processing column " + columnIndex + " value: " + originalValue);
                        
                        // Try to decrypt if it's a quoted value
                        String processedValue = AESDecryption.tryDecryptQuotedValue(originalValue, decryptedAESKeys);
                        processedLine[columnIndex] = processedValue;
                        
                        if (!processedValue.equals(originalValue)) {
                            debugPrint("DECRYPTED: " + originalValue + " -> " + processedValue);
                        } else {
                            debugPrint("UNCHANGED: " + originalValue);
                        }
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
    
    public static boolean hasParsingProblems(String file) {
        //Function to detect if CSV has parsing problems with headers
        String[] headers = getHeaders(file);
        if (headers == null) {
            return false;
        }
        
        debugPrint("=== PARSING PROBLEM DETECTION ===");
        debugPrint("Checking " + headers.length + " headers for parsing problems...");
        
        for (int i = 0; i < headers.length - 1; i++) {
            String currentHeader = headers[i];
            String nextHeader = headers[i + 1];
            
            if (currentHeader != null && nextHeader != null) {
                // Check if current header has unbalanced parentheses and next header looks like continuation
                if (hasUnbalancedParentheses(currentHeader) && looksLikeContinuation(nextHeader)) {
                    debugPrint("Problem detected at columns " + i + " and " + (i + 1));
                    debugPrint("  Current: " + currentHeader);
                    debugPrint("  Next: " + nextHeader);
                    return true;
                }
            }
        }
        
        debugPrint("No parsing problems detected");
        return false;
    }
    
    private static boolean hasUnbalancedParentheses(String header) {
        //Function to check if header has unbalanced parentheses
        if (header == null || header.trim().isEmpty()) {
            return false;
        }
        
        int openCount = 0;
        int closeCount = 0;
        
        for (char c : header.toCharArray()) {
            if (c == '(') openCount++;
            if (c == ')') closeCount++;
        }
        
        // Header has problem if it has more open than close parentheses
        boolean hasUnbalanced = openCount > closeCount;
        
        debugPrint("    Analyzing header: " + header.trim());
        debugPrint("    Open parens: " + openCount + ", Close parens: " + closeCount);
        debugPrint("    Is unbalanced: " + hasUnbalanced);
        
        return hasUnbalanced;
    }
    
    private static boolean looksLikeContinuation(String header) {
        //Function to check if header looks like a continuation of previous header
        if (header == null || header.trim().isEmpty()) {
            return false;
        }
        
        String trimmed = header.trim();
        
        // Check if it starts with ENCRYPT( (existing case)
        if (trimmed.startsWith("ENCRYPT(")) {
            debugPrint("    Continuation detected: starts with ENCRYPT(");
            return true;
        }
        
        // Check if it ends with )) which suggests it's completing parentheses
        if (trimmed.endsWith("))")) {
            debugPrint("    Continuation detected: ends with ))");
            return true;
        }
        
        // Check if it starts with lowercase or special chars (like "local))")
        if (trimmed.matches("^[a-z].*\\)+$")) {
            debugPrint("    Continuation detected: starts with lowercase and ends with )");
            return true;
        }
        
        // Check if it has more close parentheses than open (suggesting it's completing)
        int openCount = 0;
        int closeCount = 0;
        for (char c : trimmed.toCharArray()) {
            if (c == '(') openCount++;
            if (c == ')') closeCount++;
        }
        
        if (closeCount > openCount) {
            debugPrint("    Continuation detected: more close than open parentheses");
            return true;
        }
        
        debugPrint("    Not a continuation");
        return false;
    }
    
    public static boolean createArrangedCSV(String inputFile, String outputFile) {
        //Function to create arranged CSV with fixed headers and reorganized columns
        try (
                FileReader fileReader = new FileReader(inputFile);
                CSVReader csvReader = new CSVReader(fileReader);
                FileWriter fileWriter = new FileWriter(outputFile);
                CSVWriter csvWriter = new CSVWriter(fileWriter)
        ) {
            debugPrint("=== CSV ARRANGEMENT PROCESS ===");
            debugPrint("Input file: " + inputFile);
            debugPrint("Output file: " + outputFile);

            // Read all lines first
            List<String[]> allLines = new ArrayList<>();
            String[] nextLine;
            while ((nextLine = csvReader.readNext()) != null) {
                allLines.add(nextLine);
            }
            
            if (allLines.isEmpty()) {
                debugPrint("No data found in CSV file");
                return false;
            }

            // Analyze headers and create merge plan
            String[] originalHeaders = allLines.get(0);
            List<MergeOperation> mergeOperations = analyzeMergeOperations(originalHeaders);
            
            if (mergeOperations.isEmpty()) {
                debugPrint("No merge operations needed");
                // Just copy the file as-is
                for (String[] row : allLines) {
                    csvWriter.writeNext(row);
                }
                return true;
            }
            
            debugPrint("Found " + mergeOperations.size() + " merge operations");
            
            // Process headers first
            String[] arrangedHeaders = applyMergeOperationsToHeaders(originalHeaders, mergeOperations);
            csvWriter.writeNext(arrangedHeaders);
            
            // Process data rows - keep original structure but remove empty columns that correspond to merged headers
            for (int rowIndex = 1; rowIndex < allLines.size(); rowIndex++) {
                String[] originalRow = allLines.get(rowIndex);
                String[] arrangedRow = applyMergeOperationsToData(originalRow, mergeOperations);
                csvWriter.writeNext(arrangedRow);
            }

            debugPrint("=== CSV ARRANGEMENT COMPLETE ===");
            return true;

        } catch (Exception e) {
            System.err.println("Error creating arranged CSV: " + e.getMessage());
            debugPrint("=== CSV ARRANGEMENT FAILED ===");
            e.printStackTrace();
            return false;
        }
    }
    
    private static String[] applyMergeOperationsToHeaders(String[] originalHeaders, List<MergeOperation> operations) {
        //Function to apply merge operations to headers only
        String[] result = new String[originalHeaders.length];
        System.arraycopy(originalHeaders, 0, result, 0, originalHeaders.length);
        
        // Apply merge operations to headers
        for (MergeOperation op : operations) {
            if (op.sourceColumn1 < result.length && op.sourceColumn2 < result.length) {
                String value1 = result[op.sourceColumn1] != null ? result[op.sourceColumn1] : "";
                String value2 = result[op.sourceColumn2] != null ? result[op.sourceColumn2] : "";
                
                // Merge the header values
                String mergedValue = value1 + value2;
                result[op.targetColumn] = mergedValue;
                
                debugPrint("Merged header: '" + value1 + "' + '" + value2 + "' = '" + mergedValue + "'");
            }
        }
        
        // Create final array without the second column from each merge
        List<String> finalRow = new ArrayList<>();
        List<Integer> columnsToSkip = new ArrayList<>();
        
        // Collect columns that should be skipped (the second column in each merge)
        for (MergeOperation op : operations) {
            columnsToSkip.add(op.sourceColumn2);
        }
        
        // Build final row excluding skipped columns
        for (int i = 0; i < result.length; i++) {
            if (!columnsToSkip.contains(i)) {
                finalRow.add(result[i]);
            }
        }
        
        return finalRow.toArray(new String[0]);
    }
    
    private static String[] applyMergeOperationsToData(String[] originalRow, List<MergeOperation> operations) {
        //Function to keep all data values - don't skip any data even if headers are merged
        
        // For data rows, we want to keep ALL values
        // The header merging doesn't affect the data - we just return all original data
        debugPrint("Keeping all " + originalRow.length + " data values");
        
        for (int i = 0; i < originalRow.length; i++) {
            debugPrint("Keeping data value at column " + i + ": '" + originalRow[i] + "'");
        }
        
        return originalRow; // Return all original data values
    }
    
    private static class MergeOperation {
        public final int sourceColumn1;
        public final int sourceColumn2;
        public final int targetColumn;
        
        public MergeOperation(int sourceColumn1, int sourceColumn2, int targetColumn) {
            this.sourceColumn1 = sourceColumn1;
            this.sourceColumn2 = sourceColumn2;
            this.targetColumn = targetColumn;
        }
        
        @Override
        public String toString() {
            return "Merge columns " + sourceColumn1 + " and " + sourceColumn2 + " into position " + targetColumn;
        }
    }
    
    private static List<MergeOperation> analyzeMergeOperations(String[] headers) {
        //Function to analyze headers and determine what merge operations are needed
        List<MergeOperation> operations = new ArrayList<>();
        
        debugPrint("=== MERGE ANALYSIS ===");
        
        for (int i = 0; i < headers.length - 1; i++) {
            String currentHeader = headers[i];
            String nextHeader = headers[i + 1];
            
            if (currentHeader != null && nextHeader != null) {
                // Check for any unbalanced parentheses with continuation pattern
                if (hasUnbalancedParentheses(currentHeader) && looksLikeContinuation(nextHeader)) {
                    // This pair needs to be merged
                    operations.add(new MergeOperation(i, i + 1, i));
                    debugPrint("Merge operation: " + operations.get(operations.size() - 1));
                }
            }
        }
        
        debugPrint("=== MERGE ANALYSIS COMPLETE ===");
        return operations;
    }
    
    public static void debugParsingProblems(String file) {
        //Function to debug and display parsing problems
        debugPrint("=== DEBUGGING PARSING PROBLEMS ===");
        debugPrint("File: " + file);
        
        String[] headers = getHeaders(file);
        if (headers == null) {
            debugPrint("No headers found!");
            return;
        }
        
        debugPrint("Analyzing " + headers.length + " headers:");
        
        for (int i = 0; i < headers.length; i++) {
            String header = headers[i];
            debugPrint("[" + i + "] " + header);
            
            if (header != null) {
                int openCount = 0;
                int closeCount = 0;
                for (char c : header.toCharArray()) {
                    if (c == '(') openCount++;
                    if (c == ')') closeCount++;
                }
                
                if (openCount != closeCount) {
                    debugPrint("    -> UNBALANCED: " + openCount + " open, " + closeCount + " close");
                    
                    if (i < headers.length - 1) {
                        String nextHeader = headers[i + 1];
                        if (nextHeader != null && nextHeader.trim().startsWith("ENCRYPT(")) {
                            debugPrint("    -> PROBLEM: Next column starts with ENCRYPT(");
                        }
                    }
                }
            }
        }
        debugPrint("=== END DEBUGGING ===");
    }
}
