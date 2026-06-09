package dev.pluginguard.api;

import dev.pluginguard.engine.AnalysisException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.Map;

/** Translates analysis / upload errors into clean JSON error responses. */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AnalysisException.class)
    public ResponseEntity<Map<String, String>> handleAnalysis(AnalysisException ex) {
        return ResponseEntity.unprocessableEntity().body(error(ex.getMessage()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, String>> handleTooLarge(MaxUploadSizeExceededException ex) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(error("File is too large. The maximum upload size is 50 MB."));
    }

    private Map<String, String> error(String message) {
        return Map.of("error", message == null ? "Analysis failed." : message);
    }
}
