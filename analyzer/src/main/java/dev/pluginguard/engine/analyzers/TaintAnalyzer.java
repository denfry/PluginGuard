package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.TaintFlow;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Reports data-flow-confirmed dangerous flows discovered during the ASM pass (see
 * {@link dev.pluginguard.engine.bytecode.TaintScanner}). Where the {@code BytecodeAnalyzer} flags a
 * dangerous <em>capability</em> (a {@code defineClass} call exists), this flags the much stronger
 * fact that externally-influenced data actually <em>reaches</em> it — network or decoded bytes flow
 * into {@code defineClass}, the confirmed shape of a remote / encrypted payload loader.
 */
@Component
@Order(34)
public class TaintAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "taint";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        Set<String> seen = new HashSet<>();
        for (ClassScan scan : ctx.classScans()) {
            for (TaintFlow flow : scan.taintFlows()) {
                if (!TaintFlow.REMOTE_CODE_LOAD.equals(flow.sinkRuleId())) {
                    continue;
                }
                String location = scan.displayName() + "#" + flow.callerMethod();
                if (!seen.add(location)) {
                    continue;
                }
                ctx.add(Finding.builder(TaintFlow.REMOTE_CODE_LOAD, Category.CLASS_LOADING, Severity.CRITICAL)
                        .title("Loads a class from external data (data-flow confirmed)")
                        .description("Bytes from " + flow.sourceLabel() + " flow directly into defineClass(), so this "
                                + "plugin materialises and runs code that is not present in the JAR being scanned. "
                                + "Unlike a bare defineClass capability, the data-flow from the source to the class "
                                + "loader is confirmed here — the defining trait of a remote or encrypted payload loader.")
                        .recommendation("Treat as malicious unless this exact mechanism is documented and the source "
                                + "is trusted; the real code is fetched/decoded at runtime and is not in this file.")
                        .location(location)
                        .evidence(flow.sourceLabel() + " → defineClass()")
                        .nestedPath(scan.nestedPath())
                        .scoreImpact(55)
                        .build());
            }
        }
    }
}
