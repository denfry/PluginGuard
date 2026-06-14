package dev.pluginguard.engine.provenance;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.JarLoader;
import dev.pluginguard.engine.model.ClassDiff;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.ProvenanceMatch;
import dev.pluginguard.engine.model.ProvenanceReport;
import dev.pluginguard.engine.model.ProvenanceStatus;
import dev.pluginguard.engine.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Orchestrates the online authenticity check: hash-lookup first (an exact match on any source is an
 * authoritative {@code VERIFIED}), then resolve the declared identity on each source and compare. A
 * name+version match with differing bytes is {@code TAMPERED}, and — when enabled — the official jar
 * is downloaded and diffed class-by-class so the report can name the injected/modified classes. Every
 * source call fails soft: one source's outage never aborts the others.
 */
@Component
public class ProvenanceVerifier {

    private static final Logger log = LoggerFactory.getLogger(ProvenanceVerifier.class);

    /** Per-bucket cap on the class lists embedded in a diff. */
    private static final int MAX_DIFF = 50;

    private final AnalyzerProperties.Provenance cfg;
    private final ProvenanceHttp http;
    private final JarLoader jarLoader;
    private final List<OfficialSource> sources;

    public ProvenanceVerifier(AnalyzerProperties properties, ProvenanceHttp http,
                              JarLoader jarLoader, List<OfficialSource> sources) {
        this.cfg = properties.getProvenance();
        this.http = http;
        this.jarLoader = jarLoader;
        this.sources = sources;
    }

    /** Runs the full verification and returns a terminal {@link ProvenanceReport}. Never throws. */
    public ProvenanceReport verify(ScanResult result, byte[] jarBytes) {
        Instant started = Instant.now();
        Identity id = Identity.from(result);
        List<String> queried = sources.stream().map(OfficialSource::displayName).toList();
        String sha1 = Hashes.sha1(jarBytes);
        String sha256 = Hashes.sha256(jarBytes);
        String sha512 = Hashes.sha512(jarBytes);
        boolean anyError = false;

        // 1. Direct hash lookup — recognising these exact bytes is an authoritative VERIFIED.
        for (OfficialSource source : sources) {
            try {
                Optional<ProvenanceMatch> hit = source.lookupByHash(sha1, sha512);
                if (hit.isPresent()) {
                    return finish(ProvenanceStatus.VERIFIED, started, id, queried, hit.get(), null,
                            "Byte-for-byte the official release published on " + hit.get().source() + ".");
                }
            } catch (ProvenanceException e) {
                anyError = true;
                log.debug("{} hash lookup failed: {}", source.displayName(), e.toString());
            }
        }

        // 2. No usable identity to look up by name/version or repo.
        if (id.isEmpty()) {
            return finish(ProvenanceStatus.UNVERIFIED, started, id, queried, null, null,
                    "No plugin name/version or source repository was found to look up.");
        }

        // 3. Resolve the declared release on each source and compare.
        for (OfficialSource source : sources) {
            try {
                Optional<OfficialRelease> rel = source.findRelease(id);
                if (rel.isEmpty()) {
                    continue;
                }
                OfficialRelease r = rel.get();
                Comparison c = compare(r, jarBytes, result.fileName(), sha1, sha256, sha512);
                if (c == null) {
                    anyError = true; // found the listing but couldn't obtain comparable bytes
                    continue;
                }
                if (c.matched()) {
                    return finish(ProvenanceStatus.VERIFIED, started, id, queried,
                            toMatch(r, true, c.officialHash()), null,
                            "Byte-for-byte the official " + r.version() + " release on " + r.source() + ".");
                }
                return finish(ProvenanceStatus.TAMPERED, started, id, queried,
                        toMatch(r, false, c.officialHash()), c.diff(), tamperNote(r, c.diff()));
            } catch (ProvenanceException e) {
                anyError = true;
                log.debug("{} lookup failed: {}", source.displayName(), e.toString());
            }
        }

        // 4. Nothing matched.
        if (anyError) {
            return finish(ProvenanceStatus.FAILED, started, id, queried, null, null,
                    "Could not reach the official sources to verify this file; try again later.");
        }
        return finish(ProvenanceStatus.NOT_FOUND, started, id, queried, null, null, notFoundNote(id, queried));
    }

    /** The result of comparing one resolved release against the upload. {@code null} ⇒ indeterminate. */
    private record Comparison(boolean matched, ClassDiff diff, String officialHash) {
    }

    private Comparison compare(OfficialRelease r, byte[] jarBytes, String uploadedName,
                               String sha1, String sha256, String sha512) {
        // Source published a hash → compare without downloading.
        if (r.hash() != null && !r.hash().isBlank()) {
            String uploaded = switch (r.hashAlgo() == null ? "sha512" : r.hashAlgo().toLowerCase(Locale.ROOT)) {
                case "sha1" -> sha1;
                case "sha256" -> sha256;
                default -> sha512;
            };
            if (uploaded.equalsIgnoreCase(r.hash())) {
                return new Comparison(true, null, r.hash());
            }
            return new Comparison(false, maybeDiff(r, jarBytes, uploadedName), r.hash());
        }
        // No published hash (GitHub) → download and compare bytes.
        if (r.downloadUrl() == null || r.downloadUrl().isBlank()) {
            return null;
        }
        Optional<byte[]> official = http.download(r.downloadUrl(), cfg.getMaxDownloadBytes());
        if (official.isEmpty()) {
            return null;
        }
        String officialSha512 = Hashes.sha512(official.get());
        if (officialSha512.equalsIgnoreCase(sha512)) {
            return new Comparison(true, null, officialSha512);
        }
        ClassDiff diff = cfg.isDownloadDiff() ? diff(official.get(), jarBytes, r.fileName(), uploadedName) : null;
        return new Comparison(false, diff, officialSha512);
    }

    /** Downloads the official jar (if enabled) and diffs it; returns {@code null} on any problem. */
    private ClassDiff maybeDiff(OfficialRelease r, byte[] jarBytes, String uploadedName) {
        if (!cfg.isDownloadDiff() || r.downloadUrl() == null || r.downloadUrl().isBlank()) {
            return null;
        }
        try {
            Optional<byte[]> official = http.download(r.downloadUrl(), cfg.getMaxDownloadBytes());
            return official.map(bytes -> diff(bytes, jarBytes, r.fileName(), uploadedName)).orElse(null);
        } catch (ProvenanceException e) {
            log.debug("Official download for diff failed: {}", e.toString());
            return null;
        }
    }

    /** Class-level diff of two jars, keyed by human-readable class name and per-class SHA-256. */
    ClassDiff diff(byte[] officialBytes, byte[] uploadedBytes, String officialName, String uploadedName) {
        try {
            Map<String, String> off = classHashes(jarLoader.load(orDefault(officialName, "official.jar"), officialBytes));
            Map<String, String> up = classHashes(jarLoader.load(orDefault(uploadedName, "upload.jar"), uploadedBytes));

            List<String> added = new ArrayList<>();
            List<String> modified = new ArrayList<>();
            List<String> removed = new ArrayList<>();
            for (Map.Entry<String, String> e : up.entrySet()) {
                String officialHash = off.get(e.getKey());
                if (officialHash == null) {
                    added.add(e.getKey());
                } else if (!officialHash.equals(e.getValue())) {
                    modified.add(e.getKey());
                }
            }
            for (String key : off.keySet()) {
                if (!up.containsKey(key)) {
                    removed.add(key);
                }
            }
            Collections.sort(added);
            Collections.sort(modified);
            Collections.sort(removed);
            boolean truncated = added.size() > MAX_DIFF || modified.size() > MAX_DIFF || removed.size() > MAX_DIFF;
            return new ClassDiff(off.size(), up.size(), cap(added), cap(modified), cap(removed), truncated);
        } catch (RuntimeException e) {
            log.debug("Could not diff jars: {}", e.toString());
            return null;
        }
    }

    private static Map<String, String> classHashes(JarModel jar) {
        Map<String, String> out = new LinkedHashMap<>();
        for (ClassFile c : jar.classes()) {
            out.put(c.displayName(), Hashes.sha256(c.bytes()));
        }
        return out;
    }

    private static List<String> cap(List<String> list) {
        return list.size() <= MAX_DIFF ? list : new ArrayList<>(list.subList(0, MAX_DIFF));
    }

    private static ProvenanceMatch toMatch(OfficialRelease r, boolean hashMatched, String officialHash) {
        return new ProvenanceMatch(r.source(), r.projectName(), r.projectUrl(), r.version(),
                r.fileName(), officialHash, r.downloadUrl(), hashMatched);
    }

    private ProvenanceReport finish(ProvenanceStatus status, Instant started, Identity id,
                                    List<String> queried, ProvenanceMatch match, ClassDiff diff, String note) {
        Instant finished = Instant.now();
        return new ProvenanceReport(status, started, finished,
                Duration.between(started, finished).toMillis(),
                id.name(), id.version(), match, diff, queried, caveats(), note);
    }

    private static String tamperNote(OfficialRelease r, ClassDiff diff) {
        StringBuilder sb = new StringBuilder("This file claims to be ")
                .append(r.projectName())
                .append(r.version() != null ? " " + r.version() : "")
                .append(" but its bytes do not match the official release on ")
                .append(r.source()).append('.');
        if (diff != null && !diff.addedClasses().isEmpty()) {
            sb.append(" It contains ").append(diff.addedClasses().size())
                    .append(" class(es) the official build does not — likely injected code.");
        }
        return sb.toString();
    }

    private static String notFoundNote(Identity id, List<String> queried) {
        String who = id.hasName() ? id.name() + (id.hasVersion() ? " " + id.version() : "") : "this file";
        return "Could not find " + who + " on any queried official source (" + String.join(", ", queried)
                + "). Absence of a match is not proof of tampering.";
    }

    private static String orDefault(String s, String fallback) {
        return s == null || s.isBlank() ? fallback : s;
    }

    /** Honesty notes shown with every verification, mirroring the sandbox's caveats. */
    public static List<String> caveats() {
        return List.of(
                "A hash match proves the bytes are identical to the official release; it does not prove "
                        + "the official release itself is free of risk.",
                "If no official source lists this plugin, it cannot be verified — absence of a match is "
                        + "not proof of tampering.",
                "The name and version come from plugin.yml, which an attacker can forge; treat a "
                        + "\"not found\" result with appropriate caution.");
    }
}
