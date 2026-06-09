package dev.pluginguard.engine.model;

/**
 * A finding derived from observed runtime behavior in the sandbox, aggregated per
 * (event type, target). Unlike a static {@link Finding}, this is evidence the code <em>actually
 * ran</em> the action — which is most alarming when the static pass missed it
 * ({@code DYNAMIC_ONLY}).
 *
 * @param ruleId      stable id, {@code DYNAMIC_<eventType>}
 * @param eventType   the behavior kind (e.g. {@code PROCESS_EXEC})
 * @param severity    seriousness of this behavior
 * @param title       short headline
 * @param target      the concrete operand observed (command, host, class, path); may be {@code null}
 * @param blocked     whether the sandbox blocked the action (still strong evidence of intent)
 * @param occurrences how many times this (type, target) was observed
 * @param correlation whether a static finding already flagged this capability, or it is new
 * @param description plain-language explanation for an admin
 * @param recommendation what to do about it
 */
public record DynamicFinding(
        String ruleId,
        String eventType,
        Severity severity,
        String title,
        String target,
        boolean blocked,
        int occurrences,
        DynamicCorrelation correlation,
        String description,
        String recommendation) {

    /** Whether the running plugin did something no static pass had flagged. */
    public enum DynamicCorrelation {
        /** A static finding already flagged this capability — the sandbox confirms it ran. */
        CONFIRMS_STATIC,
        /** No static finding covered this — the behavior only surfaced at runtime. */
        DYNAMIC_ONLY
    }
}
