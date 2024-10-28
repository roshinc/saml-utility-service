package dev.roshin.saml.util.problem;

/**
 * Represents the problem details for error responses, conforming to RFC 7807.
 */
public record ProblemDetails(
        String type,
        String title,
        int status,
        String detail,
        String instance
) {
}
