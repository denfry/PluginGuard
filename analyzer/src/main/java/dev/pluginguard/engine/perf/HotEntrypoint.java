package dev.pluginguard.engine.perf;

/** A method that runs on the server thread frequently enough that expensive work in it hurts TPS. */
public record HotEntrypoint(String classInternalName, String methodName, Heat heat) {
}
