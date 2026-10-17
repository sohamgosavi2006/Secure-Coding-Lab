package com.securecoding.samples;

/**
 * 2. Array Boundary Validation - Corrected Implementation
 * 
 * Concept: A program attempts to access an array using an invalid index.
 * 
 * Corrected code:
 * public static int getValue(int[] numbers, int index) {
 *     if (numbers == null ||
 *         index < 0 || index >= numbers.length) {
 *         return -1;
 *     }
 *     return numbers[index];
 * }
 * 
 * The corrected method checks the array and index before accessing an element.
 */
public class ArrayBoundsFixed {

    private int[] internalBuffer;

    /**
     * Corrected method: Checks the array reference and index boundaries
     * before accessing the element (0 <= index < numbers.length).
     * Returns -1 if numbers is null or index is out of range.
     */
    public static int getValue(int[] numbers, int index) {
        if (numbers == null || index < 0 || index >= numbers.length) {
            return -1;
        }
        return numbers[index];
    }

    /**
     * Backward-compatible overload validating size before accessing index 3.
     */
    public static int getValue(int[] numbers) {
        return getValue(numbers, 3);
    }

    /**
     * Safely clones the array to prevent untrusted external mutation.
     */
    public void setBuffer(int[] buffer) {
        this.internalBuffer = (buffer != null) ? buffer.clone() : new int[0];
    }

    public int[] getBuffer() {
        return (this.internalBuffer != null) ? this.internalBuffer.clone() : new int[0];
    }
}
