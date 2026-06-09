package dev.pluginguard.engine.supplychain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies the CVSS v3 base-score calculator against published reference vectors. */
class CvssTest {

    @Test
    void computesKnownBaseScores() {
        // Canonical "worst case" — 9.8.
        assertThat(Cvss.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
                .isEqualTo(9.8);
        // Typical local privilege escalation — 7.8.
        assertThat(Cvss.baseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"))
                .isEqualTo(7.8);
        // Scope changed, full impact — 10.0.
        assertThat(Cvss.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
                .isEqualTo(10.0);
        // No impact — 0.0.
        assertThat(Cvss.baseScore("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"))
                .isEqualTo(0.0);
    }

    @Test
    void returnsNullForUnsupportedVectors() {
        assertThat(Cvss.baseScore("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")).isNull();
        assertThat(Cvss.baseScore(null)).isNull();
        assertThat(Cvss.baseScore("not a vector")).isNull();
    }
}
