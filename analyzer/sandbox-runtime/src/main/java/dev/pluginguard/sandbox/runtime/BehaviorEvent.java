package dev.pluginguard.sandbox.runtime;

/**
 * One observed runtime behavior of the analyzed plugin while it ran inside the sandbox. Events are
 * written to the structured behavior log (JSON Lines) and read back by the analyzer to build the
 * dynamic findings section of the report.
 *
 * <p>{@code blocked} records whether the sandbox actually prevented the action (e.g. the
 * SecurityManager threw, or the {@code --network none} container had no route) — a blocked attempt
 * is still strong evidence of intent.
 */
public final class BehaviorEvent {

    private final String type;
    private final String target;
    private final String detail;
    private final String source;
    private final boolean blocked;

    public BehaviorEvent(String type, String target, String detail, String source, boolean blocked) {
        this.type = type;
        this.target = target;
        this.detail = detail;
        this.source = source;
        this.blocked = blocked;
    }

    public String type() { return type; }
    public String target() { return target; }
    public String detail() { return detail; }
    public String source() { return source; }
    public boolean blocked() { return blocked; }

    /** One JSON object (no trailing newline) for the JSON Lines behavior log. */
    public String toJson() {
        return "{\"type\":" + Json.quote(type)
                + ",\"target\":" + Json.quote(target)
                + ",\"detail\":" + Json.quote(detail)
                + ",\"source\":" + Json.quote(source)
                + ",\"blocked\":" + blocked + "}";
    }

    @Override
    public String toString() {
        return toJson();
    }
}
