package org.example;

import java.io.FileReader;
import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;

import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;

public class CSVHandler {

    private static final Logger logger = Logger.getLogger(CSVHandler.class.getName());

    public static void readDataByLine(String file, String delimiter){
        //Function to read CSV format data line by line
        try (
            FileReader fileReader = new FileReader(file);
            CSVReader csvReader = new CSVReader(fileReader)
        ) {
            String[] nextRecord;

            while((nextRecord = csvReader.readNext())!= null){
                for(int i = 0; i < nextRecord.length; i++){
                    System.out.print(nextRecord[i]);
                    if (i < nextRecord.length - 1) {
                        System.out.print(delimiter);
                    }
                }
                System.out.println();
            }
        }
        catch (Exception e){
            logger.log(Level.WARNING , "Error occurs while reading data line by line", e);
        }
    }

    public static void readAllDataAtOnce(String file, String delimiter){
        try (
            FileReader fileReader = new FileReader(file);
            CSVReader csvReader = new CSVReaderBuilder(fileReader).withSkipLines(1).build()
        ) {
            List<String[]> allData = csvReader.readAll();

            //Print data
            for(String[] row: allData){
                for (int i = 0; i < row.length; i++){
                    System.out.print(row[i]);
                    if (i < row.length - 1) {
                        System.out.print(delimiter);
                    }
                }
                System.out.println();
            }
        } catch(Exception e){
            logger.log(Level.WARNING, "Error occurs while reading data all at once",e);
        }
    }
}



