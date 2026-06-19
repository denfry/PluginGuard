package dev.pluginguard.engine.model;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class CategoryAxisTest {

    @Test
    void everyCategoryHasAnAxis() {
        for (Category c : Category.values()) {
            assertThat(c.axis()).as("axis for " + c).isNotNull();
        }
    }

    @Test
    void existingSecurityCategoriesMapToSecurity() {
        assertThat(Category.NETWORK.axis()).isEqualTo(Axis.SECURITY);
        assertThat(Category.OBFUSCATION.axis()).isEqualTo(Axis.SECURITY);
        assertThat(Category.DATA_PACK.axis()).isEqualTo(Axis.SECURITY);
    }

    @Test
    void performanceCategoryMapsToPerformanceAxis() {
        assertThat(Category.PERFORMANCE.axis()).isEqualTo(Axis.PERFORMANCE);
    }
}
