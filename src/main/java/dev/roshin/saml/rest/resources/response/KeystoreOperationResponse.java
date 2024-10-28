package dev.roshin.saml.rest.resources.response;

import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.Map;

public record KeystoreOperationResponse(
        Map<String, KeystoreMetadata> providers,
        OperationSummary summary,
        Instant timestamp
) {
    public Response toResponse() {
        return Response
                .status(summary.hasErrors ?
                        (summary.successCount > 0 ? Response.Status.PARTIAL_CONTENT : Response.Status.BAD_REQUEST)
                        : Response.Status.OK)
                .entity(this)
                .build();
    }

    public record OperationSummary(
            int totalProviders,
            int successCount,
            int failureCount,
            boolean hasErrors,
            String operationId
    ) {
    }
}
