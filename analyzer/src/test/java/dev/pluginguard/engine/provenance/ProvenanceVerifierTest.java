package dev.pluginguard.engine.provenance;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.JarLoader;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.ClassDiff;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.ProvenanceMatch;
import dev.pluginguard.engine.model.ProvenanceReport;
import dev.pluginguard.engine.model.ProvenanceStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Summaries;
import dev.pluginguard.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ProvenanceVerifier}, exercising every verdict path with stubbed
 * {@link OfficialSource}s and a fake downloader — no real network.
 */
class ProvenanceVerifierTest {

    private final AnalyzerProperties props = new AnalyzerProperties();
    private final JarLoader jarLoader = new JarLoader(props);
    private final Map<String, byte[]> downloads = new HashMap<>();
    private final ProvenanceHttp http = new ProvenanceHttp(props) {
        @Override
        public Optional<byte[]> download(String url, long maxBytes) {
            return Optional.ofNullable(downloads.get(url));
        }
    };

    @Test
    void exactHashHitYieldsVerified() {
        StubSource s = new StubSource("Modrinth");
        s.hashHit = Optional.of(new ProvenanceMatch("Modrinth", "EssentialsX",
                "https://modrinth.com/plugin/essentialsx", "2.20.1", "EssentialsX.jar", "abc", null, true));

        ProvenanceReport r = verify(List.of(s), result("EssentialsX", "2.20.1"), new byte[]{1, 2, 3});

        assertThat(r.status()).isEqualTo(ProvenanceStatus.VERIFIED);
        assertThat(r.match().source()).isEqualTo("Modrinth");
        assertThat(r.match().hashMatched()).isTrue();
    }

    @Test
    void nameVersionWithMatchingHashYieldsVerified() throws IOException {
        byte[] jar = jar(Map.of("a/A.class", b("x")));
        StubSource s = new StubSource("Hangar");
        s.release = Optional.of(new OfficialRelease("Hangar", "X", "url", "1.0", "X.jar",
                "sha256", Hashes.sha256(jar), null));

        ProvenanceReport r = verify(List.of(s), result("X", "1.0"), jar);

        assertThat(r.status()).isEqualTo(ProvenanceStatus.VERIFIED);
        assertThat(r.match().hashMatched()).isTrue();
    }

    @Test
    void nameVersionWithDifferentHashYieldsTamperedWithoutDownload() {
        props.getProvenance().setDownloadDiff(false);
        StubSource s = new StubSource("Hangar");
        s.release = Optional.of(new OfficialRelease("Hangar", "X", "url", "1.0", "X.jar",
                "sha256", "deadbeef", null));

        ProvenanceReport r = verify(List.of(s), result("X", "1.0"), new byte[]{9});

        assertThat(r.status()).isEqualTo(ProvenanceStatus.TAMPERED);
        assertThat(r.match().hashMatched()).isFalse();
        assertThat(r.diff()).isNull();
    }

    @Test
    void tamperedCopyIsDiffedAgainstTheDownloadedOfficialJar() throws IOException {
        byte[] official = jar(Map.of(
                "a/A.class", b("original-A"),
                "a/B.class", b("shared-B")));
        byte[] uploaded = jar(Map.of(
                "a/A.class", b("MODIFIED-A"),
                "a/B.class", b("shared-B"),
                "evil/Backdoor.class", b("payload")));
        downloads.put("http://dl/official.jar", official);

        StubSource s = new StubSource("GitHub");
        // GitHub-style: no published hash → verifier downloads and compares bytes, then diffs.
        s.release = Optional.of(new OfficialRelease("GitHub", "owner/repo", "url", "1.0",
                "official.jar", null, null, "http://dl/official.jar"));

        ProvenanceReport r = verify(List.of(s), result("owner-repo", "1.0"), uploaded);

        assertThat(r.status()).isEqualTo(ProvenanceStatus.TAMPERED);
        ClassDiff diff = r.diff();
        assertThat(diff).isNotNull();
        assertThat(diff.addedClasses()).containsExactly("evil.Backdoor");
        assertThat(diff.modifiedClasses()).containsExactly("a.A");
        assertThat(diff.removedClasses()).isEmpty();
        assertThat(diff.officialClassCount()).isEqualTo(2);
        assertThat(diff.uploadedClassCount()).isEqualTo(3);
    }

    @Test
    void noIdentityYieldsUnverified() {
        StubSource s = new StubSource("Modrinth");
        ProvenanceReport r = verify(List.of(s), resultWithoutIdentity(), new byte[]{1});
        assertThat(r.status()).isEqualTo(ProvenanceStatus.UNVERIFIED);
    }

    @Test
    void nothingFoundYieldsNotFound() {
        StubSource s = new StubSource("Modrinth"); // returns empty for both lookups
        ProvenanceReport r = verify(List.of(s), result("Unknown", "9.9"), new byte[]{1});
        assertThat(r.status()).isEqualTo(ProvenanceStatus.NOT_FOUND);
        assertThat(r.sourcesQueried()).contains("Modrinth");
    }

    @Test
    void aSourceErrorFailsSoftAndIsReportedAsFailed() {
        StubSource s = new StubSource("Modrinth");
        s.throwOnFind = true;
        ProvenanceReport r = verify(List.of(s), result("X", "1.0"), new byte[]{1});
        assertThat(r.status()).isEqualTo(ProvenanceStatus.FAILED);
    }

    // ---- helpers ---------------------------------------------------------------------------

    private ProvenanceReport verify(List<OfficialSource> sources, ScanResult result, byte[] bytes) {
        return new ProvenanceVerifier(props, http, jarLoader, sources).verify(result, bytes);
    }

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] jar(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bos)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue());
                zos.closeEntry();
            }
        }
        return bos.toByteArray();
    }

    private static ScanResult result(String name, String version) {
        PluginInfo info = new PluginInfo("plugin.yml", name, version, "com.example.Main", "1.21",
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        return scan(info);
    }

    private static ScanResult resultWithoutIdentity() {
        return scan(null);
    }

    private static ScanResult scan(PluginInfo info) {
        List<Finding> findings = List.of();
        SeverityCounts counts = SeverityCounts.from(findings);
        Summaries summaries = new Summaries(List.of(), List.of(), List.of(), 1, 1);
        return new ScanResult("id-1", "upload.jar", "sha", 100L, "Paper", ArtifactType.PLUGIN_BUKKIT,
                info != null ? info.main() : null, "1.21", 80, Verdict.LOW_RISK, 0, counts, info,
                findings, summaries, List.of(), Instant.parse("2026-06-09T12:00:00Z"), 5L, "0.1.0",
                null, null);
    }

    private static final class StubSource implements OfficialSource {
        private final String name;
        Optional<ProvenanceMatch> hashHit = Optional.empty();
        Optional<OfficialRelease> release = Optional.empty();
        boolean throwOnFind = false;

        StubSource(String name) {
            this.name = name;
        }

        @Override
        public String displayName() {
            return name;
        }

        @Override
        public Optional<ProvenanceMatch> lookupByHash(String sha1, String sha512) {
            return hashHit;
        }

        @Override
        public Optional<OfficialRelease> findRelease(Identity id) {
            if (throwOnFind) {
                throw new ProvenanceException("boom");
            }
            return release;
        }
    }
}
