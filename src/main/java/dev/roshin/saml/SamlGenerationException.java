package dev.roshin.saml;

/**
 * Custom exception for SAML generation errors
 */
class SamlGenerationException extends RuntimeException {
    public SamlGenerationException(String message) {
        super(message);
    }

    public SamlGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}