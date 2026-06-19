package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;

import java.util.ArrayDeque;
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

    /** Adjacency: caller node key -> set of in-jar callee node keys. */
    private final Map<String, Set<String>> edges = new HashMap<>();

    public CallGraph(List<ClassScan> classes) {
        Set<String> jarOwners = new HashSet<>();
        for (ClassScan c : classes) {
            jarOwners.add(c.internalName());
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
     * BFS from each hot entrypoint up to {@code maxDepth}. Every reachable method (including the
     * entrypoints at distance 0) is recorded with the HOTTEST heat and the SHORTEST distance seen,
     * merged independently — they may come from different paths. A node is re-queued whenever either
     * improves, so the result is independent of edge/arrival order. Improvements are monotone (heat
     * only gets hotter, distance only gets shorter) and bounded, so the BFS always terminates.
     */
    public Map<String, Reach> reachableFrom(List<HotEntrypoint> entrypoints, int maxDepth) {
        Map<String, Reach> result = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();

        for (HotEntrypoint ep : entrypoints) {
            String k = key(ep.classInternalName(), ep.methodName());
            if (merge(result, k, ep.heat(), 0)) {
                queue.add(k);
            }
        }

        while (!queue.isEmpty()) {
            String node = queue.poll();
            Reach here = result.get(node);
            if (here.distance() >= maxDepth) {
                continue;
            }
            int nextDist = here.distance() + 1;
            for (String next : edges.getOrDefault(node, Set.of())) {
                if (merge(result, next, here.heat(), nextDist)) {
                    queue.add(next);
                }
            }
        }
        return result;
    }

    /** Merge a candidate (heat, distance) into a node's best-known reach; returns true if it improved. */
    private static boolean merge(Map<String, Reach> result, String key, Heat heat, int distance) {
        Reach existing = result.get(key);
        if (existing == null) {
            result.put(key, new Reach(heat, distance));
            return true;
        }
        Heat bestHeat = hotter(heat, existing.heat()) ? heat : existing.heat();
        int bestDist = Math.min(distance, existing.distance());
        if (bestHeat == existing.heat() && bestDist == existing.distance()) {
            return false;
        }
        result.put(key, new Reach(bestHeat, bestDist));
        return true;
    }

    private static boolean hotter(Heat a, Heat b) {
        return a.ordinal() < b.ordinal(); // HOT(0) < WARM(1) < COOL(2)
    }
}
