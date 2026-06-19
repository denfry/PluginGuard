package dev.pluginguard.engine.model;

import java.util.List;

/**
 * A combined, plain-language install recommendation across all populated axes. This is a
 * recommendation, not a guarantee — the per-axis breakdown is always shown alongside it.
 *
 * @param level    the headline guidance level
 * @param headline one-line reason naming the dominant axis
 * @param perAxis  one short line per populated axis
 */
public record Recommendation(RecommendationLevel level, String headline, List<String> perAxis) {

    public Recommendation {
        perAxis = perAxis == null ? List.of() : List.copyOf(perAxis);
    }
}
