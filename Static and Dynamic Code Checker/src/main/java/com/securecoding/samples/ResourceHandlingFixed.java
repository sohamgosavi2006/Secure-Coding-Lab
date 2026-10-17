package com.securecoding.samples;

import java.io.*;
import java.nio.file.*;

/**
 * 4. Unclosed I/O Resource Leak - Corrected Implementation
 * 
 * Concept: A program opens a file but fails to close the resource after using it.
 * 
 * Corrected code:
 * import java.io.*;
 * import java.nio.file.*;
 * 
 * public static String readFile(Path path) throws IOException {
 *     try (BufferedReader reader = Files.newBufferedReader(path)) {
 *         return reader.readLine();
 *     }
 * }
 * 
 * The try-with-resources statement closes the reader automatically,
 * including when an exception occurs.
 */
public class ResourceHandlingFixed {

    /**
     * Corrected method: Uses Java try-with-resources statement.
     * Closes the reader automatically upon exit or exception.
     */
    public static String readFile(Path path) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            return reader.readLine();
        }
    }
}
