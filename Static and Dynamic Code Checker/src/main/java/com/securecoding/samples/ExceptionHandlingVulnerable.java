package com.securecoding.samples;

/**
 * 3. Suppressed Exception Handling - Vulnerable Implementation
 * 
 * Concept: A program catches an exception but silently ignores it, hiding the problem.
 * 
 * Vulnerable code:
 * public static void calculate() {
 *     try {
 *         int result = 10 / 0;
 *     } catch (ArithmeticException e) {
 *     }
 * }
 * 
 * The exception is swallowed, so the program gives no indication that the calculation failed.
 * 
 * What your tools demonstrate:
 * - Static Analysis (PMD): Identifies EmptyCatchBlock (Avoid empty catch blocks).
 * - Static Analysis (SpotBugs): Detects dead stores / suppressed failure patterns.
 * - Dynamic Testing (JUnit 5): Verifies silent failure vs reporting mechanism.
 */
public class ExceptionHandlingVulnerable {

    private static boolean wasSuccess = false;

    /**
     * Vulnerable method: Catches ArithmeticException from 10 / 0 but leaves catch block empty.
     * The exception is swallowed, so the program gives no indication that the calculation failed.
     */
    public static void calculate() {
        try {
            int result = 10 / 0;
            wasSuccess = true;
        } catch (ArithmeticException e) {
            // Defect: Empty catch block silently swallows runtime failure!
            // PMD Rule: EmptyCatchBlock
        }
    }

    public static boolean isCalculationSuccessful() {
        return wasSuccess;
    }
}
