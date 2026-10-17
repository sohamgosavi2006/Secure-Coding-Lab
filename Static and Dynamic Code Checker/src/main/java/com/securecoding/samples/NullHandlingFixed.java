package com.securecoding.samples;

/**
 * 1. Null Pointer Dereference - Corrected Implementation
 * 
 * Concept: A program tries to use an object reference that is null.
 * 
 * Corrected code:
 * public static int getLength(String text) {
 *     if (text == null) {
 *         return 0;
 *     }
 *     return text.length();
 * }
 * 
 * The corrected method handles null without throwing that exception.
 * Returning zero is a chosen example behaviour; another application
 * might reject null input instead.
 */
public class NullHandlingFixed {

    /**
     * Corrected method: Defensively checks if text is null before calling .length().
     * Returns 0 for null input, preventing any NullPointerException.
     */
    public static int getLength(String text) {
        if (text == null) {
            return 0;
        }
        return text.length();
    }

    /**
     * Safe invocation path validating inputs before processing.
     */
    public static int processInput() {
        String text = null;
        return getLength(text); // Safely returns 0
    }

    /**
     * Proper defensive null check using logical OR (||) and safe branch handling.
     */
    public static int checkAndGetLength(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        return text.length();
    }
}
