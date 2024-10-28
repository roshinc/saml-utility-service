package dev.roshin.saml.rest.resources.response;

import java.time.Instant;

public record ErrorResponse(
        String message,
        String operationId,
        Instant timestamp,
        String errorType
) {
}