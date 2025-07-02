package org.example;

import java.io.*;
import java.awt.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import  java.util.Scanner;

class Main{
    public static void main(String[] args){
        Scanner scanner = new Scanner(System.in);

        System.out.println("Please enter your CSV file's path");
        String filePath = scanner.nextLine();
        CSVHandler.readDataByLine(filePath, ",");

        scanner.close();
    }
}