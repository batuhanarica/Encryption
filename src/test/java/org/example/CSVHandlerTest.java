package org.example;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;
import java.io.*;
import java.nio.file.*;

class CSVHandlerTest {
    
    private final ByteArrayOutputStream outputStreamCaptor = new ByteArrayOutputStream();
    private final PrintStream standardOut = System.out;
    private static final String TEST_CSV_CONTENT = "Name,Age,City\nJohn,25,New York\nJane,30,Los Angeles\nBob,35,Chicago";
    private static final String TEST_CSV_SINGLE_LINE = "Name,Age,City";
    private static final String TEST_CSV_EMPTY = "";
    private static final String TEST_CSV_WITH_COMMAS = "Product,Price,Description\nLaptop,999.99,\"High-end gaming laptop, 16GB RAM\"\nMouse,29.99,\"Wireless mouse\"";
    
    private Path testCsvFile;
    private Path testCsvSingleLine;
    private Path testCsvEmpty;
    private Path testCsvWithCommas;

    @BeforeEach
    void setUp() throws IOException {
        // Redirect System.out to capture console output
        System.setOut(new PrintStream(outputStreamCaptor));
        
        // Create temporary test CSV files
        testCsvFile = Files.createTempFile("test", ".csv");
        Files.write(testCsvFile, TEST_CSV_CONTENT.getBytes());
        
        testCsvSingleLine = Files.createTempFile("testSingle", ".csv");
        Files.write(testCsvSingleLine, TEST_CSV_SINGLE_LINE.getBytes());
        
        testCsvEmpty = Files.createTempFile("testEmpty", ".csv");
        Files.write(testCsvEmpty, TEST_CSV_EMPTY.getBytes());
        
        testCsvWithCommas = Files.createTempFile("testCommas", ".csv");
        Files.write(testCsvWithCommas, TEST_CSV_WITH_COMMAS.getBytes());
    }

    @AfterEach
    void tearDown() throws IOException {
        // Restore original System.out
        System.setOut(standardOut);
        outputStreamCaptor.reset();
        
        // Clean up temporary files
        Files.deleteIfExists(testCsvFile);
        Files.deleteIfExists(testCsvSingleLine);
        Files.deleteIfExists(testCsvEmpty);
        Files.deleteIfExists(testCsvWithCommas);
    }

    // Tests for readDataByLine method
    
    @Test
    @DisplayName("Test readDataByLine with valid CSV file and comma delimiter")
    void testReadDataByLineWithValidFile() {
        CSVHandler.readDataByLine(testCsvFile.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        assertEquals(4, lines.length);
        assertEquals("Name,Age,City", lines[0]);
        assertEquals("John,25,New York", lines[1]);
        assertEquals("Jane,30,Los Angeles", lines[2]);
        assertEquals("Bob,35,Chicago", lines[3]);
    }
    
    @Test
    @DisplayName("Test readDataByLine with custom delimiter")
    void testReadDataByLineWithCustomDelimiter() {
        CSVHandler.readDataByLine(testCsvFile.toString(), " | ");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        assertEquals(4, lines.length);
        assertEquals("Name | Age | City", lines[0]);
        assertEquals("John | 25 | New York", lines[1]);
        assertEquals("Jane | 30 | Los Angeles", lines[2]);
        assertEquals("Bob | 35 | Chicago", lines[3]);
    }
    
    @Test
    @DisplayName("Test readDataByLine with single line CSV")
    void testReadDataByLineWithSingleLine() {
        CSVHandler.readDataByLine(testCsvSingleLine.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        assertEquals(1, lines.length);
        assertEquals("Name,Age,City", lines[0]);
    }
    
    @Test
    @DisplayName("Test readDataByLine with empty CSV file")
    void testReadDataByLineWithEmptyFile() {
        CSVHandler.readDataByLine(testCsvEmpty.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        assertEquals("", output.trim());
    }
    
    @Test
    @DisplayName("Test readDataByLine with non-existent file")
    void testReadDataByLineWithNonExistentFile() {
        CSVHandler.readDataByLine("non_existent_file.csv", ",");
        
        // Should not throw exception due to internal exception handling
        // Method should complete without crashing
        assertDoesNotThrow(() -> {
            CSVHandler.readDataByLine("non_existent_file.csv", ",");
        });
    }
    
    @Test
    @DisplayName("Test readDataByLine with CSV containing commas in quoted fields")
    void testReadDataByLineWithQuotedFields() {
        CSVHandler.readDataByLine(testCsvWithCommas.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        assertEquals(3, lines.length);
        assertEquals("Product,Price,Description", lines[0]);
        assertEquals("Laptop,999.99,High-end gaming laptop, 16GB RAM", lines[1]);
        assertEquals("Mouse,29.99,Wireless mouse", lines[2]);
    }

    // Tests for readAllDataAtOnce method
    
    @Test
    @DisplayName("Test readAllDataAtOnce with valid CSV file and comma delimiter")
    void testReadAllDataAtOnceWithValidFile() {
        CSVHandler.readAllDataAtOnce(testCsvFile.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        // Should skip first line (header), so only 3 data lines
        assertEquals(3, lines.length);
        assertEquals("John,25,New York", lines[0]);
        assertEquals("Jane,30,Los Angeles", lines[1]);
        assertEquals("Bob,35,Chicago", lines[2]);
    }
    
    @Test
    @DisplayName("Test readAllDataAtOnce with custom delimiter")
    void testReadAllDataAtOnceWithCustomDelimiter() {
        CSVHandler.readAllDataAtOnce(testCsvFile.toString(), " | ");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        // Should skip first line (header), so only 3 data lines
        assertEquals(3, lines.length);
        assertEquals("John | 25 | New York", lines[0]);
        assertEquals("Jane | 30 | Los Angeles", lines[1]);
        assertEquals("Bob | 35 | Chicago", lines[2]);
    }
    
    @Test
    @DisplayName("Test readAllDataAtOnce with single line CSV (header only)")
    void testReadAllDataAtOnceWithSingleLine() {
        CSVHandler.readAllDataAtOnce(testCsvSingleLine.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        // Should skip the single line (header), so no output
        assertEquals("", output.trim());
    }
    
    @Test
    @DisplayName("Test readAllDataAtOnce with empty CSV file")
    void testReadAllDataAtOnceWithEmptyFile() {
        CSVHandler.readAllDataAtOnce(testCsvEmpty.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        assertEquals("", output.trim());
    }
    
    @Test
    @DisplayName("Test readAllDataAtOnce with non-existent file")
    void testReadAllDataAtOnceWithNonExistentFile() {
        CSVHandler.readAllDataAtOnce("non_existent_file.csv", ",");
        
        // Should not throw exception due to internal exception handling
        // Method should complete without crashing
        assertDoesNotThrow(() -> {
            CSVHandler.readAllDataAtOnce("non_existent_file.csv", ",");
        });
    }
    
    @Test
    @DisplayName("Test readAllDataAtOnce with CSV containing commas in quoted fields")
    void testReadAllDataAtOnceWithQuotedFields() {
        CSVHandler.readAllDataAtOnce(testCsvWithCommas.toString(), ",");
        
        String output = outputStreamCaptor.toString();
        String[] lines = output.split(System.lineSeparator());
        
        // Should skip first line (header), so only 2 data lines
        assertEquals(2, lines.length);
        assertEquals("Laptop,999.99,High-end gaming laptop, 16GB RAM", lines[0]);
        assertEquals("Mouse,29.99,Wireless mouse", lines[1]);
    }
    
    @Test
    @DisplayName("Test readAllDataAtOnce with null file path")
    void testReadAllDataAtOnceWithNullPath() {
        assertDoesNotThrow(() -> {
            CSVHandler.readAllDataAtOnce(null, ",");
        });
    }
    
    @Test
    @DisplayName("Test readDataByLine with null file path")
    void testReadDataByLineWithNullPath() {
        assertDoesNotThrow(() -> {
            CSVHandler.readDataByLine(null, ",");
        });
    }
}