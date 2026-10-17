package com.securecoding.tests;

import com.securecoding.samples.ArrayBoundsVulnerable;
import com.securecoding.samples.ArrayBoundsFixed;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("2. Array Boundary Validation Test Suite")
public class ArrayBoundsTest {

    @Test
    @DisplayName("Vulnerable: Array with 4 elements retrieves index 3 successfully")
    public void testVulnerableSufficientLength() {
        int[] fourElements = { 10, 20, 30, 40 };
        assertEquals(40, ArrayBoundsVulnerable.getValue(fourElements));
    }

    @Test
    @DisplayName("Vulnerable: Array with 3 elements causes ArrayIndexOutOfBoundsException")
    public void testVulnerableThreeElementsThrowsException() {
        // Demonstrates defect: array with 3 elements (indices 0, 1, 2) causes index 3 out of bounds
        int[] threeElements = { 10, 20, 30 };
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            ArrayBoundsVulnerable.getValue(threeElements);
        });
    }

    @Test
    @DisplayName("Fixed: Valid index accesses element correctly")
    public void testFixedValidIndex() {
        int[] numbers = { 10, 20, 30, 40 };
        assertEquals(20, ArrayBoundsFixed.getValue(numbers, 1));
        assertEquals(40, ArrayBoundsFixed.getValue(numbers, 3));
    }

    @Test
    @DisplayName("Fixed: Out-of-range index safely returns -1 fallback")
    public void testFixedOutOfRangeReturnsFallback() {
        int[] threeElements = { 10, 20, 30 };
        // Index 3 is out of range for 3 elements: returns -1 instead of throwing exception
        assertEquals(-1, ArrayBoundsFixed.getValue(threeElements, 3));
        assertEquals(-1, ArrayBoundsFixed.getValue(threeElements));
    }

    @Test
    @DisplayName("Fixed: Negative index safely returns -1 fallback")
    public void testFixedNegativeIndexReturnsFallback() {
        int[] numbers = { 10, 20, 30 };
        assertEquals(-1, ArrayBoundsFixed.getValue(numbers, -1));
    }

    @Test
    @DisplayName("Fixed: Null array safely returns -1 fallback")
    public void testFixedNullArrayReturnsFallback() {
        assertEquals(-1, ArrayBoundsFixed.getValue(null, 0));
    }

    @Test
    @DisplayName("Fixed: Buffer getter/setter safe array cloning")
    public void testFixedBufferCloning() {
        ArrayBoundsFixed fixed = new ArrayBoundsFixed();
        int[] buf = { 1, 2, 3 };
        fixed.setBuffer(buf);
        assertArrayEquals(buf, fixed.getBuffer());
        assertNotSame(buf, fixed.getBuffer());
    }
}
