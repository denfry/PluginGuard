package dev.pluginguard.engine.sandbox;

import dev.pluginguard.engine.model.BehaviorEvent;
import dev.pluginguard.engine.model.SandboxStatus;

import java.util.List;

/**
 * Result of a {@link SandboxRunner} run: a terminal status, the behavior events read back from the
 * container, and a human-readable note (e.g. why it was unavailable or timed out).
 */
public record SandboxOutcome(
        SandboxStatus status,
        List<BehaviorEvent> events,
        String note) {

    public static SandboxOutcome unavailable(String note) {
        return new SandboxOutcome(SandboxStatus.UNAVAILABLE, List.of(), note);
    }

    public static SandboxOutcome failed(List<BehaviorEvent> events, String note) {
        return new SandboxOutcome(SandboxStatus.FAILED, events, note);
    }

    public static SandboxOutcome completed(List<BehaviorEvent> events, String note) {
        return new SandboxOutcome(SandboxStatus.COMPLETED, events, note);
    }
}
