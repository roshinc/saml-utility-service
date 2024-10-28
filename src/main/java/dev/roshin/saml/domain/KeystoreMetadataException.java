package dev.roshin.saml.domain;

/**
 * Exception thrown when there are issues retrieving keystore metadata.
 */
public class KeystoreMetadataException extends Exception {
    public KeystoreMetadataException(String message) {
        super(message);
    }

    public KeystoreMetadataException(String message, Throwable cause) {
        super(message, cause);
    }
}