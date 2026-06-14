package dev.pluginguard.api.auth;

import java.util.Locale;

/**
 * Billing plan of an organization. The monthly scan limit is the metered quota enforced by
 * {@link ApiAccessService}. Values are deliberate, illustrative defaults — a later slice can make
 * them configurable / Stripe-driven.
 */
public enum Plan {
    FREE(100),
    PRO(10_000),
    BUSINESS(200_000);

    private final int monthlyScanLimit;

    Plan(int monthlyScanLimit) {
        this.monthlyScanLimit = monthlyScanLimit;
    }

    public int monthlyScanLimit() {
        return monthlyScanLimit;
    }

    /** Whether this plan includes the (compute-heavy) dynamic sandbox — a paid feature. */
    public boolean dynamicSandbox() {
        return this != FREE;
    }

    /** Lenient parse — unknown / null values fall back to {@link #FREE}. */
    public static Plan fromString(String value) {
        if (value == null || value.isBlank()) {
            return FREE;
        }
        try {
            return valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return FREE;
        }
    }
}
