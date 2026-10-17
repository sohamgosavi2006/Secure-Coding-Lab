package com.securecoding.tests;

import com.securecoding.samples.NullHandlingVulnerable;
import com.securecoding.samples.NullHandlingFixed;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("1. Null Pointer Dereference Test Suite")
public class NullHandlingTest {

    @Test
    @DisplayName("Vulnerable: Valid string returns correct length")
    public void testVulnerableValidString() {
        assertEquals(5, NullHandlingVulnerable.getLength("Hello"));
    }

    @Test
    @DisplayName("Vulnerable: Unhandled null input throws NullPointerException (Defect Reproduced)")
    public void testVulnerableNullThrowsException() {
        // Asserting that passing null triggers the expected NullPointerException at runtime.
        // The JUnit test assertion passes because the vulnerability was reproduced as expected.
        assertThrows(NullPointerException.class, () -> {
            NullHandlingVulnerable.getLength(null);
        });
    }

    @Test
    @DisplayName("Fixed: Valid string returns correct length")
    public void testFixedValidString() {
        assertEquals(5, NullHandlingFixed.getLength("Hello"));
    }

    @Test
    @DisplayName("Fixed: Passing null safely returns 0 without exception")
    public void testFixedNullSafelyReturnsZero() {
        // Demonstrates defensive correction: if (text == null) return 0;
        assertEquals(0, NullHandlingFixed.getLength(null));
    }

    @Test
    @DisplayName("Fixed: Process input handles null safely")
    public void testFixedProcessInput() {
        assertEquals(0, NullHandlingFixed.processInput());
    }

    @Test
    @DisplayName("Fixed: Check and get length handles empty and valid strings")
    public void testFixedCheckAndGetLength() {
        assertEquals(0, NullHandlingFixed.checkAndGetLength(null));
        assertEquals(0, NullHandlingFixed.checkAndGetLength(""));
        assertEquals(4, NullHandlingFixed.checkAndGetLength("Java"));
    }
}
