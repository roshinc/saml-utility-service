package dev.roshin.saml.config;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

@ApplicationScoped
public class SamlConfigurationManager {
    private static final Logger logger = LoggerFactory.getLogger(SamlConfigurationManager.class);
    private static final Gson gson = new Gson();
    private final AtomicReference<SamlConfiguration> currentConfig = new AtomicReference<>();
    @Inject
    @ConfigProperty(name = "saml.config.cache.refresh.seconds", defaultValue = "-1")
    private long cacheRefreshSeconds;

    @Inject
    @ConfigProperty(name = "saml.config.endpoint.url")
    private String configEndpointUrl;

    private volatile Instant lastRefresh = Instant.EPOCH;

    public SamlConfiguration getConfiguration() {
        if (shouldRefresh()) {
            synchronized (this) {
                if (shouldRefresh()) {
                    refreshConfiguration();
                }
            }
        }
        return currentConfig.get();
    }

    private boolean shouldRefresh() {
        return cacheRefreshSeconds > 0 &&
                Instant.now().isAfter(lastRefresh.plusSeconds(cacheRefreshSeconds));
    }

    private void refreshConfiguration() {
        try {
            String jsonResponse = fetchConfigurationFromRestEndpoint();
            SamlConfiguration newConfig = parseConfiguration(jsonResponse);
            currentConfig.set(newConfig);
            lastRefresh = Instant.now();
            logger.info("SAML configuration refreshed successfully");
        } catch (Exception e) {
            logger.error("Failed to refresh SAML configuration", e);
            throw new RuntimeException("Failed to refresh SAML configuration", e);
        }
    }

    private String fetchConfigurationFromRestEndpoint() {
        return SamlConfigurationFetcher.fetchConfiguration(configEndpointUrl);
    }

    private SamlConfiguration parseConfiguration(String jsonResponse) {
        JsonObject json = gson.fromJson(jsonResponse, JsonObject.class);
        return SamlConfiguration.fromJson(json);
    }
}

