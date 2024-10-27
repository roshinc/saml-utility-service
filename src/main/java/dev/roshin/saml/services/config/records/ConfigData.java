package dev.roshin.saml.services.config.records;

import java.util.Map;

/**
 * Represents the combined configurations: general and provider-specific.
 */
public record ConfigData(
        GeneralConfig generalConfig,
        Map<String, ProviderConfig> providerConfigs
) {
}
