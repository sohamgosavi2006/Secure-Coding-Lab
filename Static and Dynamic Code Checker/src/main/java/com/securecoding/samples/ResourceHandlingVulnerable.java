package com.securecoding.samples;

import java.io.*;
import java.nio.file.*;

/**
 * 4. Unclosed I/O Resource Leak - Vulnerable Implementation
 * 
 * Concept: A program opens a file but fails to close the resource after using it.
 * 
 * Vulnerable code:
 * import java.io.*;
 * import java.nio.file.*;
 * 
 * public static String readFile(Path path) throws IOException {
 *     BufferedReader reader = Files.newBufferedReader(path);
 *     return reader.readLine();
 * }
 * 
 * The reader is never explicitly closed, which may leave an operating-system resource in use.
 * 
 * What your tools demonstrate:
 * - Static Analysis (SpotBugs): Detects OS_OPEN_STREAM (Method may fail to close stream).
 * - Static Analysis (PMD): Detects CloseResource (Ensure BufferedReader is closed after use).
 * - Dynamic Testing (JUnit 5): Verifies file reading functionality.
 * - Code Coverage (JaCoCo): Measures execution coverage during I/O operations.
 */
public class ResourceHandlingVulnerable {

    /**
     * Vulnerable method: Allocates BufferedReader without closing it.
     * The reader is never explicitly closed, which leaves an OS resource in use.
     */
    public static String readFile(Path path) throws IOException {
        BufferedReader reader = Files.newBufferedReader(path);
        return reader.readLine();
    }
}
