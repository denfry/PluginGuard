package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Estimates how obfuscated the code is from naming statistics (very short class/method names,
 * default-package usage), reflection density and encoded-blob density, producing a 0–100
 * obfuscation score (higher = more obfuscated). Obfuscation alone is not malicious, so the
 * score only contributes meaningful deductions when it is high.
 */
@Component
@Order(50)
public class ObfuscationAnalyzer implements Analyzer {

    private static final Pattern SHORT_NAME = Pattern.compile("[A-Za-z$]{1,2}");
    private static final Pattern BASE64_BLOB = Pattern.compile("[A-Za-z0-9+/]{120,}={0,2}");

    private static final Set<String> REFLECTION_OWNERS = Set.of(
            "java/lang/invoke/MethodHandles$Lookup");

    @Override
    public String name() {
        return "obfuscation";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        List<ClassScan> classes = ctx.classScans().stream().filter(ClassScan::parsed).toList();
        if (classes.isEmpty()) {
            ctx.setObfuscationScore(0);
            return;
        }

        int shortClasses = 0;
        int defaultPackage = 0;
        int totalMethods = 0;
        int shortMethods = 0;
        int reflectionCalls = 0;
        int totalCalls = 0;
        int base64Count = 0;

        for (ClassScan scan : classes) {
            String internal = scan.internalName();
            String simpleName = internal.contains("/")
                    ? internal.substring(internal.lastIndexOf('/') + 1)
                    : internal;
            if (SHORT_NAME.matcher(simpleName).matches()) {
                shortClasses++;
            }
            if (!internal.contains("/")) {
                defaultPackage++;
            }
            for (MethodInfo m : scan.methods()) {
                if (m.name().startsWith("<")) {
                    continue; // skip <init>/<clinit>
                }
                totalMethods++;
                if (SHORT_NAME.matcher(m.name()).matches()) {
                    shortMethods++;
                }
            }
            for (Invocation inv : scan.invocations()) {
                totalCalls++;
                if (isReflection(inv)) {
                    reflectionCalls++;
                }
            }
            for (String s : scan.stringConstants()) {
                if (BASE64_BLOB.matcher(s).find()) {
                    base64Count++;
                }
            }
        }

        double shortClassFrac = shortClasses / (double) classes.size();
        double defaultPkgFrac = defaultPackage / (double) classes.size();
        double shortMethodFrac = totalMethods == 0 ? 0 : shortMethods / (double) totalMethods;
        double reflectionFrac = totalCalls == 0 ? 0 : reflectionCalls / (double) totalCalls;
        double base64Density = Math.min(1.0, base64Count / (double) classes.size());

        int score = (int) Math.round(
                shortClassFrac * 35
                        + shortMethodFrac * 35
                        + defaultPkgFrac * 10
                        + reflectionFrac * 10
                        + base64Density * 10);
        score = Math.max(0, Math.min(100, score));
        ctx.setObfuscationScore(score);

        List<String> reasons = new ArrayList<>();
        if (shortClassFrac > 0.3) reasons.add(pct(shortClassFrac) + " of classes have 1–2 character names");
        if (shortMethodFrac > 0.3) reasons.add(pct(shortMethodFrac) + " of methods have 1–2 character names");
        if (defaultPkgFrac > 0.3) reasons.add(pct(defaultPkgFrac) + " of classes use no package");
        if (reflectionFrac > 0.1) reasons.add(pct(reflectionFrac) + " of calls are reflective");
        if (base64Count >= 5) reasons.add(base64Count + " base64-like blobs");
        String reasonText = reasons.isEmpty() ? "" : " (" + String.join("; ", reasons) + ")";

        if (score >= 70) {
            ctx.add(Finding.builder("OBFUSCATION_HIGH", Category.OBFUSCATION, Severity.MEDIUM)
                    .title("Heavily obfuscated code")
                    .description("Obfuscation score " + score + "/100" + reasonText + ". Heavy obfuscation is legitimate "
                            + "for some commercial plugins, but it also hides what the code does and frequently "
                            + "accompanies malicious behaviour.")
                    .recommendation("Prefer plugins whose source or behaviour you can verify, especially if other "
                            + "findings are present.")
                    .evidence("score " + score + "/100")
                    .scoreImpact(15)
                    .build());
        } else if (score >= 45) {
            ctx.add(Finding.builder("OBFUSCATION_MODERATE", Category.OBFUSCATION, Severity.LOW)
                    .title("Noticeable obfuscation")
                    .description("Obfuscation score " + score + "/100" + reasonText + ".")
                    .recommendation("Common for protected plugins; review more carefully if combined with risky calls.")
                    .evidence("score " + score + "/100")
                    .scoreImpact(6)
                    .build());
        } else if (score >= 25) {
            ctx.add(Finding.builder("OBFUSCATION_LOW", Category.OBFUSCATION, Severity.INFO)
                    .title("Some obfuscation detected")
                    .description("Obfuscation score " + score + "/100" + reasonText + ".")
                    .recommendation("Low level — typically not a concern on its own.")
                    .evidence("score " + score + "/100")
                    .scoreImpact(0)
                    .build());
        }
    }

    private boolean isReflection(Invocation inv) {
        if (REFLECTION_OWNERS.contains(inv.owner())) {
            return true;
        }
        if (inv.owner().startsWith("java/lang/reflect/")) {
            return true;
        }
        if (inv.owner().equals("java/lang/Class")) {
            String n = inv.name();
            return n.equals("forName") || n.startsWith("getDeclared") || n.startsWith("getMethod")
                    || n.startsWith("getField") || n.equals("getMethods") || n.equals("getFields");
        }
        return false;
    }

    private static String pct(double frac) {
        return Math.round(frac * 100) + "%";
    }
}
