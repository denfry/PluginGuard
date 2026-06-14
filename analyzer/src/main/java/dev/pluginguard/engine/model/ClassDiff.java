package dev.pluginguard.engine.model;

import java.util.List;

/**
 * The class-level difference between the uploaded jar and the genuine official release, computed when
 * a tampered copy is detected. {@code addedClasses} are the strongest signal — classes present in the
 * upload but absent from the official build are code an attacker injected (a backdoor). Class names
 * are dotted and human-readable. Lists are capped for the report; {@link #truncated()} flags when more
 * existed. Part of the JSON API contract.
 *
 * @param officialClassCount number of classes in the official release
 * @param uploadedClassCount number of classes in the uploaded file
 * @param addedClasses       classes in the upload that the official build does not have (injected)
 * @param modifiedClasses    classes present in both but whose bytes differ (patched)
 * @param removedClasses     classes in the official build that the upload dropped
 * @param truncated          whether any of the lists were capped (more differences existed)
 */
public record ClassDiff(
        int officialClassCount,
        int uploadedClassCount,
        List<String> addedClasses,
        List<String> modifiedClasses,
        List<String> removedClasses,
        boolean truncated) {

    public ClassDiff {
        addedClasses = addedClasses == null ? List.of() : List.copyOf(addedClasses);
        modifiedClasses = modifiedClasses == null ? List.of() : List.copyOf(modifiedClasses);
        removedClasses = removedClasses == null ? List.of() : List.copyOf(removedClasses);
    }

    /** Total number of differing classes (added + modified + removed). */
    public int totalChanges() {
        return addedClasses.size() + modifiedClasses.size() + removedClasses.size();
    }
}
