package com.securecoding.tests;

import com.securecoding.samples.ResourceHandlingVulnerable;
import com.securecoding.samples.ResourceHandlingFixed;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("4. Unclosed I/O Resource Leak Test Suite")
public class ResourceHandlingTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Vulnerable: Reads first line from file but leaves stream unclosed")
    public void testVulnerableReadsFile() throws IOException {
        Path tempFile = tempDir.resolve("sample-vuln.txt");
        Files.writeString(tempFile, "SECURE_DATA_LINE_1\nLINE_2\n");

        String line = ResourceHandlingVulnerable.readFile(tempFile);
        assertEquals("SECURE_DATA_LINE_1", line);
    }

    @Test
    @DisplayName("Fixed: Reads first line safely with try-with-resources auto-closure")
    public void testFixedReadsFileSafely() throws IOException {
        Path tempFile = tempDir.resolve("sample-fixed.txt");
        Files.writeString(tempFile, "SECURE_DATA_FIXED_1\nLINE_2\n");

        String line = ResourceHandlingFixed.readFile(tempFile);
        assertEquals("SECURE_DATA_FIXED_1", line);
    }
}
