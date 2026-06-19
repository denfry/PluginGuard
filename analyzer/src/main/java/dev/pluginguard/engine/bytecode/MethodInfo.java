package dev.pluginguard.engine.bytecode;

import java.util.List;

/** Minimal info about a declared method: name, descriptor, and annotation descriptors. */
public record MethodInfo(String name, String descriptor, List<String> annotations) {

    public MethodInfo {
        annotations = annotations == null ? List.of() : List.copyOf(annotations);
    }

    /** Backwards-compatible constructor for callers that don't track annotations. */
    public MethodInfo(String name, String descriptor) {
        this(name, descriptor, List.of());
    }
}
