package dev.pluginguard.engine.perf;

import java.util.List;
import java.util.Optional;

/**
 * The table of method calls that are expensive on the server thread. Matching is by owner internal
 * name + method name (descriptor-independent), mirroring how the rest of the engine matches calls.
 */
public final class PerfSinkTable {

    public enum SinkWeight { LIGHT, MODERATE, HEAVY, SEVERE }

    /**
     * @param title                 short headline for the finding
     * @param weight                intrinsic cost
     * @param alwaysBadOnMainThread floor the severity at MEDIUM even in a low-frequency context
     * @param recommendation        what the admin/dev should do
     */
    public record PerfSink(String title, SinkWeight weight, boolean alwaysBadOnMainThread, String recommendation) {
    }

    private record Rule(String owner, String method, PerfSink sink) {
    }

    private static final String FIX_ASYNC =
            "Move this off the main server thread (e.g. an async task) and cache the result.";

    private static final List<Rule> RULES = List.of(
            // Blocking I/O — SEVERE, always bad on the main thread.
            rule("java/sql/DriverManager", "getConnection", "Opens a database connection on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/Statement", "executeQuery", "Runs a database query on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/Statement", "execute", "Runs a database statement on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/Statement", "executeUpdate", "Runs a database update on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/PreparedStatement", "execute", "Runs a prepared statement on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/PreparedStatement", "executeQuery", "Runs a prepared query on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/HttpURLConnection", "getInputStream", "Blocking HTTP request on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/HttpURLConnection", "connect", "Blocking HTTP connect on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/http/HttpClient", "send", "Synchronous HTTP request on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/Socket", "connect", "Opens a network socket on the server thread",
                    SinkWeight.SEVERE, true),

            // Blocking waits — HEAVY, always bad on the main thread.
            rule("java/lang/Thread", "sleep", "Sleeps the calling thread", SinkWeight.HEAVY, true),
            rule("java/lang/Object", "wait", "Blocks the calling thread on a monitor", SinkWeight.HEAVY, true),
            rule("java/util/concurrent/Future", "get", "Blocks waiting for a future result", SinkWeight.HEAVY, true),
            rule("java/util/concurrent/CompletableFuture", "join", "Blocks joining a future", SinkWeight.HEAVY, true),
            rule("java/util/concurrent/CompletableFuture", "get", "Blocks waiting for a future", SinkWeight.HEAVY, true),

            // Synchronous world / chunk operations — HEAVY, always bad.
            rule("org/bukkit/World", "getChunkAt", "Loads/generates a chunk synchronously", SinkWeight.HEAVY, true),
            rule("org/bukkit/World", "loadChunk", "Loads a chunk synchronously", SinkWeight.HEAVY, true),

            // Hot-path anti-patterns — MODERATE.
            rule("java/util/regex/Pattern", "compile", "Compiles a regex in a hot path (should be a static field)",
                    SinkWeight.MODERATE, false),
            rule("org/bukkit/Bukkit", "getOnlinePlayers", "Iterates all online players in a hot path",
                    SinkWeight.MODERATE, false));

    private static Rule rule(String owner, String method, String title, SinkWeight w, boolean alwaysBad) {
        return new Rule(owner, method, new PerfSink(title, w, alwaysBad, FIX_ASYNC));
    }

    private PerfSinkTable() {
    }

    public static Optional<PerfSink> match(String ownerInternalName, String methodName) {
        for (Rule r : RULES) {
            if (r.owner.equals(ownerInternalName) && r.method.equals(methodName)) {
                return Optional.of(r.sink);
            }
        }
        return Optional.empty();
    }
}
