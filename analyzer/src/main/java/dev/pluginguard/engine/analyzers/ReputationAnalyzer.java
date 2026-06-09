package dev.pluginguard.engine.analyzers;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.supplychain.ReputationService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Set;

/**
 * Phase&nbsp;2 SHA-256 reputation. Compares the hash of the uploaded JAR and of any bundled nested
 * archives against pull-able lists: a hit on the <em>known-malicious</em> list is a Critical finding
 * (a previously-identified bad file), while a hit on the <em>known-good</em> list is recorded as a
 * reassuring informational note. Disabled by default.
 */
@Component
@Order(12)
public class ReputationAnalyzer implements Analyzer {

    private final AnalyzerProperties.SupplyChain cfg;
    private final ReputationService reputation;

    public ReputationAnalyzer(AnalyzerProperties properties, ReputationService reputation) {
        this.cfg = properties.getSupplyChain();
        this.reputation = reputation;
    }

    @Override
    public String name() {
        return "reputation";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        if (!cfg.isReputationEnabled()) {
            return;
        }
        Set<String> malicious = reputation.knownMalicious();
        Set<String> good = reputation.knownGood();
        if (malicious.isEmpty() && good.isEmpty()) {
            return;
        }

        // Top-level JAR.
        check(ctx, ctx.jar().sha256(), "this file", null, malicious, good);

        // Bundled nested archives (their bytes were retained during loading).
        for (ResourceFile res : ctx.jar().resources()) {
            String lower = res.name().toLowerCase(Locale.ROOT);
            if (lower.endsWith(".jar") || lower.endsWith(".zip") || lower.endsWith(".war")) {
                check(ctx, sha256(res.bytes()), "bundled archive '" + res.displayName() + "'",
                        res.nested() ? res.container() : null, malicious, good);
            }
        }
    }

    private void check(AnalysisContext ctx, String hash, String what, String nestedPath,
                       Set<String> malicious, Set<String> good) {
        if (hash == null) {
            return;
        }
        String h = hash.toLowerCase(Locale.ROOT);
        if (malicious.contains(h)) {
            ctx.add(Finding.builder("REPUTATION_KNOWN_MALICIOUS", Category.SUPPLY_CHAIN, Severity.CRITICAL)
                    .title("Matches a known-malicious file (SHA-256)")
                    .description("The SHA-256 of " + what + " matches a known-malicious hash list. This exact file "
                            + "(byte-for-byte) was previously identified as malicious.")
                    .recommendation("Do not install. Delete the file and obtain the plugin from a trusted source.")
                    .evidence(h)
                    .nestedPath(nestedPath)
                    .scoreImpact(80)
                    .build());
        } else if (good.contains(h)) {
            ctx.add(Finding.builder("REPUTATION_KNOWN_GOOD", Category.SUPPLY_CHAIN, Severity.INFO)
                    .title("Matches a known-good release (SHA-256)")
                    .description("The SHA-256 of " + what + " matches a known-good hash list, i.e. it is a recognised, "
                            + "unmodified release. This lowers (but does not eliminate) risk.")
                    .recommendation("Still review other findings; a known-good hash only proves the bytes are unchanged.")
                    .evidence(h)
                    .nestedPath(nestedPath)
                    .scoreImpact(0)
                    .build());
        }
    }

    private static String sha256(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
