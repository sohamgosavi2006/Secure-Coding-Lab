package com.securecoding.samples;

/**
 * 2. Array Boundary Validation - Vulnerable Implementation
 * 
 * Concept: A program attempts to access an array using an invalid index.
 * 
 * Vulnerable code:
 * public static int getValue(int[] numbers) {
 *     return numbers[3];
 * }
 * 
 * If the array contains only three elements, its valid indices are 0, 1 and 2.
 * Index 3 causes an ArrayIndexOutOfBoundsException.
 * 
 * What your tools demonstrate:
 * - Dynamic Testing (JUnit 5): Passes an array of size 3 to verify ArrayIndexOutOfBoundsException.
 * - Static Analysis (SpotBugs): Detects RANGE_ARRAY_INDEX out-of-bounds access.
 * - Static Analysis (PMD): Identifies array exposure and validation issues.
 * - Code Coverage (JaCoCo): Measures execution of boundary validation logic.
 */
public class ArrayBoundsVulnerable {

    private int[] internalBuffer;

    /**
     * Vulnerable method: Attempts to access index 3 without bounds validation.
     * If numbers has fewer than 4 elements (e.g. size 3), throws ArrayIndexOutOfBoundsException.
     */
    public static int getValue(int[] numbers) {
        return numbers[3];
    }

    /**
     * Demonstrates static array boundary violation on 3-element buffer (valid indices 0, 1, 2).
     * SpotBugs flags RANGE_ARRAY_INDEX (Array index is out of bounds).
     */
    public static int getThirdElement() {
        int[] sample = new int[3]; // size 3: valid indices are 0, 1, 2
        return sample[3]; // Defect: index 3 causes ArrayIndexOutOfBoundsException
    }

    /**
     * Storing user-supplied array directly into internal field exposes internal representation.
     * PMD flags ArrayIsStoredDirectly.
     */
    public void setBuffer(int[] buffer) {
        this.internalBuffer = buffer;
    }

    public int[] getBuffer() {
        return this.internalBuffer;
    }
}
