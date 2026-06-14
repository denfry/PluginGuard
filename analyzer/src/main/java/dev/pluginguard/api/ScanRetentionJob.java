package dev.pluginguard.api;

import dev.pluginguard.config.AnalyzerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Purges stored reports older than the configured TTL. Active only under the {@code postgres}
 * profile (the in-memory store is self-bounded). Scheduling is enabled by {@code SchedulingConfig}.
 */
@Component
@Profile("postgres")
public class ScanRetentionJob {

    private static final Logger log = LoggerFactory.getLogger(ScanRetentionJob.class);

    private final JdbcTemplate jdbc;
    private final AnalyzerProperties.Retention cfg;

    public ScanRetentionJob(JdbcTemplate jdbc, AnalyzerProperties properties) {
        this.jdbc = jdbc;
        this.cfg = properties.getRetention();
    }

    /** Runs hourly, deleting rows whose {@code created_at} is older than the TTL. */
    @Scheduled(fixedDelayString = "PT1H")
    public void purgeExpired() {
        int ttlDays = cfg.getReportTtlDays();
        if (ttlDays <= 0) {
            return; // retention disabled
        }
        int deleted = jdbc.update(
                "DELETE FROM scan WHERE created_at < now() - make_interval(days => ?)", ttlDays);
        if (deleted > 0) {
            log.info("Retention: purged {} report(s) older than {} day(s).", deleted, ttlDays);
        }
    }
}
