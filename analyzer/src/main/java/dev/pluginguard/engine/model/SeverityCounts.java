package dev.pluginguard.engine.model;

import java.util.List;

/** Count of findings per severity level, for the report header. */
public record SeverityCounts(int critical, int high, int medium, int low, int info) {

    public static SeverityCounts from(List<Finding> findings) {
        int c = 0, h = 0, m = 0, l = 0, i = 0;
        for (Finding f : findings) {
            switch (f.severity()) {
                case CRITICAL -> c++;
                case HIGH -> h++;
                case MEDIUM -> m++;
                case LOW -> l++;
                case INFO -> i++;
            }
        }
        return new SeverityCounts(c, h, m, l, i);
    }

    public int total() {
        return critical + high + medium + low + info;
    }
}
