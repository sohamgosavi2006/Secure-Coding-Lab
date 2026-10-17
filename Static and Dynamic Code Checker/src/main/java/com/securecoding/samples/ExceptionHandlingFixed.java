package com.securecoding.samples;

/**
 * 3. Suppressed Exception Handling - Corrected Implementation
 * 
 * Concept: A program catches an exception but silently ignores it, hiding the problem.
 * 
 * Corrected code:
 * public static void calculate() {
 *     try {
 *         int result = 10 / 0;
 *     } catch (ArithmeticException e) {
 *         System.err.println(
 *             "Calculation failed: " + e.getMessage()
 *         );
 *     }
 * }
 * 
 * The corrected version reports the failure instead of silently ignoring it.
 */
public class ExceptionHandlingFixed {

    private static boolean wasSuccess = false;
    private static String lastErrorMessage = null;

    /**
     * Corrected method: Reports the failure instead of silently ignoring it.
     * Logs the diagnostic error message to stderr and records the failure state.
     */
    public static void calculate() {
        try {
            int result = 10 / 0;
            wasSuccess = true;
            lastErrorMessage = null;
            System.out.println("Result: " + result);
        } catch (ArithmeticException e) {
            wasSuccess = false;
            lastErrorMessage = e.getMessage();
            System.err.println(
                "Calculation failed: " + e.getMessage()
            );
        }
    }

    public static boolean isCalculationSuccessful() {
        return wasSuccess;
    }

    public static String getLastErrorMessage() {
        return lastErrorMessage;
    }
}
