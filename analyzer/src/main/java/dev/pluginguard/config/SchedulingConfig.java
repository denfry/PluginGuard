package dev.pluginguard.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables {@code @Scheduled} tasks only under the {@code postgres} profile (the only profile with
 * background jobs — see {@code ScanRetentionJob}). The default in-memory profile needs no scheduler.
 */
@Configuration
@Profile("postgres")
@EnableScheduling
public class SchedulingConfig {
}
