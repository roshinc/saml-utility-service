package dev.roshin.saml.services.config.records;

/**
 * Represents the configuration for a provider.
 */
public record ProviderConfig(
        String keyAlias,
        String keystoreFile,
        String keystorePassword,
        String parseEncoding
) {
}
