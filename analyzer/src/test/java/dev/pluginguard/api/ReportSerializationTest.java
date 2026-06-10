package dev.pluginguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.engine.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link JdbcReportStore} persists a report as the JSON the API returns and reads it back. This
 * verifies that round-trip is lossless with the application's real (jsr310-aware) {@link ObjectMapper}
 * — every nested record/enum/Instant must deserialize cleanly, or durable reports would be unreadable.
 */
@SpringBootTest
class ReportSerializationTest {

    @Autowired
    ObjectMapper mapper;

    @Test
    void scanResultSurvivesJsonRoundTrip() throws Exception {
        ScanResult original = DemoData.sample();

        String json = mapper.writeValueAsString(original);
        ScanResult restored = mapper.readValue(json, ScanResult.class);
        String reserialized = mapper.writeValueAsString(restored);

        // Re-serializing the restored object yields identical JSON ⇒ nothing was lost in the round trip.
        assertThat(reserialized).isEqualTo(json);
        assertThat(restored.id()).isEqualTo("demo");
        assertThat(restored.verdict()).isEqualTo(original.verdict());
        assertThat(restored.findings()).hasSameSizeAs(original.findings());
        assertThat(restored.sandbox().status()).isEqualTo(original.sandbox().status());
        assertThat(restored.analyzedAt()).isEqualTo(original.analyzedAt());
    }
}
