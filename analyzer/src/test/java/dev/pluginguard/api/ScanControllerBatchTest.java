package dev.pluginguard.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Bulk-scan endpoint behavior in the default (no API layer) profile: a file that can't be scanned
 * becomes a per-item error rather than failing the whole batch.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerBatchTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void batchCapturesPerFileErrorsWithoutFailingTheRequest() throws Exception {
        MockMultipartFile a = new MockMultipartFile("files", "a.txt", "text/plain", new byte[]{1, 2, 3});
        MockMultipartFile b = new MockMultipartFile("files", "b.txt", "text/plain", new byte[]{4, 5, 6});

        mvc.perform(multipart("/api/scan/batch").file(a).file(b))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].fileName").value("a.txt"))
                .andExpect(jsonPath("$[0].error").exists())
                .andExpect(jsonPath("$[1].error").exists());
    }
}
