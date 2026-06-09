package dev.pluginguard.sandbox.runtime;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe sink for {@link BehaviorEvent}s. Events are always kept in memory (so an in-process
 * harness test can drain them) and, when a file is configured, also appended as JSON Lines so the
 * orchestrating analyzer can read them after the container exits.
 */
public final class BehaviorLog {

    private final List<BehaviorEvent> events = new CopyOnWriteArrayList<>();
    private final Writer out; // nullable: memory-only when running in-process

    public BehaviorLog() {
        this.out = null;
    }

    private BehaviorLog(Writer out) {
        this.out = out;
    }

    /** Opens a file-backed log (used inside the container); the parent directory must exist. */
    public static BehaviorLog toFile(Path path) {
        try {
            Writer w = new BufferedWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8));
            return new BehaviorLog(w);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot open behavior log " + path, e);
        }
    }

    public void record(BehaviorEvent event) {
        events.add(event);
        if (out != null) {
            synchronized (this) {
                try {
                    out.write(event.toJson());
                    out.write('\n');
                    out.flush();
                } catch (IOException e) {
                    // A logging failure must never crash the harness; drop silently.
                }
            }
        }
    }

    public List<BehaviorEvent> events() {
        return List.copyOf(events);
    }

    public void close() {
        if (out != null) {
            synchronized (this) {
                try {
                    out.close();
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }
}
