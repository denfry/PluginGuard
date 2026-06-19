package dev.pluginguard.engine.model;

/**
 * The score for one {@link Axis}, computed from only that axis's findings.
 *
 * @param axis     the analysis dimension
 * @param score    0–100 (higher is better) for this axis alone
 * @param verdict  risk band for this axis
 * @param counts   finding counts (this axis only)
 * @param headline one-line plain-language summary
 */
public record AxisScore(Axis axis, int score, Verdict verdict, SeverityCounts counts, String headline) {
}
