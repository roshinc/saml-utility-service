package dev.roshin.saml.services.config.fetcher;

import java.util.Map;

/**
 * Interface for fetching configuration data.
 */
public interface ConfigFetcher {
    Map<String, String> getConfig();
}
