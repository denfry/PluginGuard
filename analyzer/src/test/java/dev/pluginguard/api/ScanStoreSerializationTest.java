package dev.pluginguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import dev.pluginguard.engine.model.ScanResult;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the JSONB persistence assumption of {@link JdbcScanStore}: a full report must survive a
 * Jackson serialize → deserialize round-trip. Pure unit test — no database required.
 */
class ScanStoreSerializationTest {

    @Test
    void scanResultSurvivesJsonRoundTrip() throws Exception {
        ObjectMapper mapper = JsonMapper.builder().findAndAddModules().build();
        ScanResult original = DemoData.sample();

        String json = mapper.writeValueAsString(original);
        ScanResult restored = mapper.readValue(json, ScanResult.class);

        assertThat(restored.id()).isEqualTo(original.id());
        assertThat(restored.sha256()).isEqualTo(original.sha256());
        assertThat(restored.score()).isEqualTo(original.score());
        assertThat(restored.verdict()).isEqualTo(original.verdict());
        assertThat(restored.artifactType()).isEqualTo(original.artifactType());
        assertThat(restored.analyzedAt()).isEqualTo(original.analyzedAt());
        assertThat(restored.findings()).hasSameSizeAs(original.findings());
    }
}
