package dev.pluginguard.engine.supplychain;

import java.util.HashMap;
import java.util.Map;

/**
 * Computes a CVSS v3.0/v3.1 base score (0.0–10.0) from a vector string, e.g.
 * {@code CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}. OSV advisories carry these vectors for CVE
 * entries; the resulting score lets us map a vulnerability to a {@code Severity} band. Returns
 * {@code null} for vectors we don't understand (CVSS v2 / v4), so the caller can fall back.
 */
public final class Cvss {

    private Cvss() {
    }

    /** Parses a CVSS v3 vector and returns the base score, or {@code null} if not a v3 vector. */
    public static Double baseScore(String vector) {
        if (vector == null || !vector.startsWith("CVSS:3")) {
            return null;
        }
        Map<String, String> m = new HashMap<>();
        for (String part : vector.split("/")) {
            int eq = part.indexOf(':');
            if (eq > 0) {
                m.put(part.substring(0, eq), part.substring(eq + 1));
            }
        }
        try {
            boolean scopeChanged = "C".equals(m.get("S"));
            double av = switch (m.get("AV")) {
                case "N" -> 0.85; case "A" -> 0.62; case "L" -> 0.55; case "P" -> 0.2;
                default -> throw new IllegalArgumentException();
            };
            double ac = "H".equals(m.get("AC")) ? 0.44 : 0.77;
            double pr = privilegesRequired(m.get("PR"), scopeChanged);
            double ui = "R".equals(m.get("UI")) ? 0.62 : 0.85;
            double c = impactMetric(m.get("C"));
            double i = impactMetric(m.get("I"));
            double a = impactMetric(m.get("A"));

            double iscBase = 1 - ((1 - c) * (1 - i) * (1 - a));
            double impact = scopeChanged
                    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
                    : 6.42 * iscBase;
            if (impact <= 0) {
                return 0.0;
            }
            double exploitability = 8.22 * av * ac * pr * ui;
            double raw = scopeChanged
                    ? Math.min(1.08 * (impact + exploitability), 10)
                    : Math.min(impact + exploitability, 10);
            return roundUp(raw);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static double privilegesRequired(String pr, boolean scopeChanged) {
        return switch (pr) {
            case "N" -> 0.85;
            case "L" -> scopeChanged ? 0.68 : 0.62;
            case "H" -> scopeChanged ? 0.5 : 0.27;
            default -> throw new IllegalArgumentException();
        };
    }

    private static double impactMetric(String v) {
        return switch (v) {
            case "H" -> 0.56; case "L" -> 0.22; case "N" -> 0.0;
            default -> throw new IllegalArgumentException();
        };
    }

    /** CVSS "roundup": smallest one-decimal number >= the input (with float-tolerance). */
    private static double roundUp(double value) {
        int scaled = (int) Math.round(value * 100000);
        if (scaled % 10000 == 0) {
            return scaled / 100000.0;
        }
        return (Math.floor(scaled / 10000.0) + 1) / 10.0;
    }
}
