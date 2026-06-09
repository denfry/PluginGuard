package dev.pluginguard.engine.bytecode;

/** Minimal info about a declared method, used for obfuscation name statistics. */
public record MethodInfo(String name, String descriptor) {
}
