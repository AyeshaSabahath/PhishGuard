package com.phishguard;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class PredictionController {

    private final PhishingDetectorService detector;

    public PredictionController(PhishingDetectorService detector) {
        this.detector = detector;
    }

    @PostMapping("/predict")
    public ResponseEntity<?> predict(@RequestBody PredictionRequest request) {
        try {
            if (request == null || request.url() == null || request.url().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Please enter a URL."));
            }
            return ResponseEntity.ok(detector.predict(request.url()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Unexpected server error."));
        }
    }

    public record PredictionRequest(String url) {}
}
