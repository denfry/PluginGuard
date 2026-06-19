package dev.pluginguard.engine.perf;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class PerfSinkTableTest {

    @Test
    void jdbcConnectionIsASevereAlwaysBadSink() {
        var sink = PerfSinkTable.match("java/sql/DriverManager", "getConnection").orElseThrow();
        assertThat(sink.weight()).isEqualTo(PerfSinkTable.SinkWeight.SEVERE);
        assertThat(sink.alwaysBadOnMainThread()).isTrue();
    }

    @Test
    void threadSleepIsHeavyAndAlwaysBad() {
        var sink = PerfSinkTable.match("java/lang/Thread", "sleep").orElseThrow();
        assertThat(sink.weight()).isEqualTo(PerfSinkTable.SinkWeight.HEAVY);
        assertThat(sink.alwaysBadOnMainThread()).isTrue();
    }

    @Test
    void ordinaryCallIsNotASink() {
        assertThat(PerfSinkTable.match("java/lang/String", "length")).isEmpty();
    }

    @Test
    void patternCompileIsModerate() {
        var sink = PerfSinkTable.match("java/util/regex/Pattern", "compile").orElseThrow();
        assertThat(sink.weight()).isEqualTo(PerfSinkTable.SinkWeight.MODERATE);
    }
}
