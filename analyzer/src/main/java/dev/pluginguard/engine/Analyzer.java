package dev.pluginguard.engine;

/**
 * A single analysis pass. Implementations inspect the {@link AnalysisContext} (JAR model and
 * pre-computed class scans) and contribute findings / summary data. Analyzers run in registration
 * order; later analyzers may rely on signals set by earlier ones (e.g. the obfuscation analyzer
 * reads counts populated by the bytecode analyzer).
 *
 * <p>Implementations must be stateless and side-effect-free beyond mutating the supplied context,
 * and must never load or execute any class from the JAR.
 */
public interface Analyzer {

    /** Stable, human-readable name (for logs and ordering). */
    String name();

    /** Inspects the context and records findings / summary data. */
    void analyze(AnalysisContext context);
}
