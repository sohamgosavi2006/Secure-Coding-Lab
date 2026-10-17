package com.securecoding.tests;

import com.securecoding.samples.ExceptionHandlingVulnerable;
import com.securecoding.samples.ExceptionHandlingFixed;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("3. Suppressed Exception Handling Test Suite")
public class ExceptionHandlingTest {

    @Test
    @DisplayName("Vulnerable: Swallows division by zero without reporting")
    public void testVulnerableSwallowsException() {
        // In vulnerable version, calculate() executes 10 / 0 and empty catch block swallows failure
        ExceptionHandlingVulnerable.calculate();
        assertFalse(ExceptionHandlingVulnerable.isCalculationSuccessful());
    }

    @Test
    @DisplayName("Fixed: Reports failure instead of silently ignoring it")
    public void testFixedReportsFailure() {
        // In fixed version, calculate() catches failure, logs it, and records error message
        ExceptionHandlingFixed.calculate();
        assertFalse(ExceptionHandlingFixed.isCalculationSuccessful());
        assertNotNull(ExceptionHandlingFixed.getLastErrorMessage());
        assertTrue(ExceptionHandlingFixed.getLastErrorMessage().contains("by zero") || ExceptionHandlingFixed.getLastErrorMessage().contains("/ by zero"));
    }
}
