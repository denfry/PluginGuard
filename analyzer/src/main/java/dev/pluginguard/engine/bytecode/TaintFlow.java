package dev.pluginguard.engine.bytecode;

/**
 * A confirmed intraprocedural data-flow from a taint source to a dangerous sink, found by
 * {@link TaintScanner}. Unlike a capability match (the sink is merely <em>present</em>), this records
 * that externally-influenced data actually reaches the sink argument.
 *
 * @param sinkRuleId   the rule id for the sink that was reached (e.g. {@code TAINT_REMOTE_CODE_LOAD})
 * @param callerMethod the method in which the flow was observed (for the report location)
 * @param sourceLabel  a short label naming where the data came from (e.g. "the network")
 */
public record TaintFlow(String sinkRuleId, String callerMethod, String sourceLabel) {

    /** Rule id: external data flows into {@code defineClass}, i.e. code is materialised from it. */
    public static final String REMOTE_CODE_LOAD = "TAINT_REMOTE_CODE_LOAD";
}
