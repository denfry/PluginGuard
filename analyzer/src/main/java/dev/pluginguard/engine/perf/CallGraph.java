package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An intra-jar call graph built from captured invocations. A node is a method, keyed by
 * {@code classInternalName + "#" + methodName} (descriptor-less, matching {@link Invocation}'s
 * caller identity). Edges point from a caller method to every in-jar callee method with the called
 * name. Reachability is a bounded BFS from the hot entrypoints; each reached node keeps the best
 * (highest) heat and the shortest distance found.
 */
public final class CallGraph {

    /** Reachability info for one method: the inherited heat and the shortest call distance. */
    public record Reach(Heat heat, int distance) {
    }

    /** Method names declared in the jar, grouped by owner internal name. */
    private final Map<String, Set<String>> methodsByOwner = new HashMap<>();
    /** Adjacency: caller node key -> set of in-jar callee node keys. */
    private final Map<String, Set<String>> edges = new HashMap<>();

    public CallGraph(List<ClassScan> classes) {
        Set<String> jarOwners = new HashSet<>();
        for (ClassScan c : classes) {
            jarOwners.add(c.internalName());
            Set<String> names = methodsByOwner.computeIfAbsent(c.internalName(), k -> new HashSet<>());
            c.methods().forEach(m -> names.add(m.name()));
        }
        for (ClassScan c : classes) {
            for (Invocation inv : c.invocations()) {
                if (!jarOwners.contains(inv.owner())) {
                    continue; // callee is a library/JDK class — not a graph edge
                }
                String from = key(inv.callerClass(), inv.callerMethod());
                String to = key(inv.owner(), inv.name());
                edges.computeIfAbsent(from, k -> new HashSet<>()).add(to);
            }
        }
    }

    /** Stable node key for (class, method). */
    public static String key(String classInternalName, String methodName) {
        return classInternalName + "#" + methodName;
    }

    /**
     * BFS from each hot entrypoint up to {@code maxDepth}. The returned map holds every reachable
     * method (including the entrypoints at distance 0) with its best heat and shortest distance.
     */
    public Map<String, Reach> reachableFrom(List<HotEntrypoint> entrypoints, int maxDepth) {
        Map<String, Reach> result = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        Map<String, Heat> entryHeat = new HashMap<>();

        for (HotEntrypoint ep : entrypoints) {
            String k = key(ep.classInternalName(), ep.methodName());
            // Seed; if seen twice keep the hotter.
            if (!result.containsKey(k) || hotter(ep.heat(), result.get(k).heat())) {
                result.put(k, new Reach(ep.heat(), 0));
                entryHeat.put(k, ep.heat());
                queue.add(k);
            }
        }

        while (!queue.isEmpty()) {
            String node = queue.poll();
            Reach here = result.get(node);
            if (here.distance() >= maxDepth) {
                continue;
            }
            for (String next : edges.getOrDefault(node, Set.of())) {
                Reach existing = result.get(next);
                int nextDist = here.distance() + 1;
                if (existing == null || nextDist < existing.distance() || hotter(here.heat(), existing.heat())) {
                    result.put(next, new Reach(here.heat(), Math.min(nextDist,
                            existing == null ? nextDist : existing.distance())));
                    queue.add(next);
                }
            }
        }
        return result;
    }

    private static boolean hotter(Heat a, Heat b) {
        return a.ordinal() < b.ordinal(); // HOT(0) < WARM(1) < COOL(2)
    }
}
