package com.securecoding.samples;

/**
 * 1. Null Pointer Dereference - Vulnerable Implementation
 * 
 * Concept: A program tries to use an object reference that is null.
 * 
 * Vulnerable code:
 * public static int getLength(String text) {
 *     return text.length();
 * }
 * 
 * If text is null, calling text.length() throws a NullPointerException.
 * 
 * What your tools demonstrate:
 * - Dynamic Testing (JUnit 5): Passes null to getLength() to prove runtime NullPointerException.
 * - Static Analysis (PMD & SpotBugs): Identifies unsafe null dereference patterns.
 * - Code Coverage (JaCoCo): Measures execution of null-handling branches.
 */
public class NullHandlingVulnerable {

    /**
     * Vulnerable method: Directly dereferences text without checking for null.
     * If text is null, calling text.length() throws a NullPointerException.
     */
    public static int getLength(String text) {
        return text.length();
    }

    /**
     * Unsafe invocation path demonstrating passing a null reference.
     * Static bytecode analysis (SpotBugs NP_NULL_PARAM_DEREF_NONVIRTUAL) flags
     * this unvalidated parameter passing.
     */
    public static int processInput() {
        String unvalidatedText = null;
        return getLength(unvalidatedText);
    }

    /**
     * Broken null validation check: uses && instead of ||, dereferencing null.
     * Static AST analysis (PMD BrokenNullCheck) flags this unsafe pattern.
     */
    public static int checkAndGetLength(String text) {
        if (text == null && text.length() > 0) {
            return text.length();
        }
        return 0;
    }
}
