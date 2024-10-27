package dev.roshin.saml.services.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.roshin.saml.services.config.fetcher.ConfigFetcher;
import dev.roshin.saml.services.config.fetcher.ProviderConfigParser;
import dev.roshin.saml.services.config.records.ConfigData;
import dev.roshin.saml.services.config.records.GeneralConfig;
import dev.roshin.saml.services.config.records.ProviderConfig;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Manages provider configurations with caching and optional refresh interval.
 */
@ApplicationScoped
public class ConfigManager {

    private static final Logger logger = LoggerFactory.getLogger(ConfigManager.class);
    private static final String CACHE_KEY = "configs";
    private static final String CONFIG_REFRESH_PROPERTY = "saml.config.cache.refresh.seconds";
    private static final int MAX_RETRY_ATTEMPTS = 3;

    @Inject
    protected ConfigFetcher configFetcher;

    private Cache<String, ConfigData> configCache;
    private Optional<Long> cacheRefreshSecondsOpt;


    /**
     * Initializes the configuration cache with optional refresh interval.
     * Validates configuration parameters and sets up the cache with appropriate settings.
     *
     * @throws ConfigurationException if initialization fails or configuration is invalid
     */
    @PostConstruct
    public void init() {
        logger.debug("Initializing ConfigManager...");
        try {
            // Build the cache, applying expiration if CACHE_REFRESH is provided
            Caffeine<Object, Object> caffeineBuilder = Caffeine.newBuilder();
            initializeCacheSettings(caffeineBuilder);
            validateInitialConfiguration();
            logger.info("ConfigManager initialized successfully");
        } catch (Exception e) {
            logger.error("Critical failure during ConfigManager initialization", e);
            throw new ConfigurationException("Failed to initialize ConfigManager", e);
        }
    }

    /**
     * Initializes cache settings with validation of refresh interval.
     *
     * @param caffeineBuilder the Caffeine builder instance
     * @throws ConfigurationException if refresh interval is invalid
     */
    private void initializeCacheSettings(Caffeine<Object, Object> caffeineBuilder) {
        cacheRefreshSecondsOpt = ConfigProvider.getConfig().getOptionalValue(CONFIG_REFRESH_PROPERTY, Long.class);
        if (cacheRefreshSecondsOpt.isPresent()) {
            long cacheRefreshSeconds = cacheRefreshSecondsOpt.get();

            logger.info("Configuring cache with refresh interval of {} seconds", cacheRefreshSeconds);
            caffeineBuilder.expireAfterWrite(Duration.ofSeconds(cacheRefreshSeconds));
        } else {
            logger.warn("No cache refresh interval configured - cache entries will not expire automatically");
        }

        this.configCache = caffeineBuilder.build();
    }

    /**
     * Retrieves the combined SAML configurations with retry mechanism and monitoring.
     *
     * @return ConfigData containing both general and provider-specific configurations
     * @throws ConfigurationException if configuration cannot be retrieved after retries
     */
    public ConfigData getConfigData() {
        for (int attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
            try {
                int finalAttempt = attempt;
                return configCache.get(CACHE_KEY, key -> {
                    logger.info("Cache miss (attempt {}/{}) - fetching fresh configurations",
                            finalAttempt, MAX_RETRY_ATTEMPTS);
                    return fetchConfigurations();
                });
            } catch (Exception e) {
                if (attempt == MAX_RETRY_ATTEMPTS) {
                    logger.error("Failed to retrieve configuration data after {} attempts",
                            MAX_RETRY_ATTEMPTS, e);
                    throw new ConfigurationException(
                            "Failed to retrieve configuration data after multiple attempts", e);
                }
                logger.warn("Attempt {}/{} failed, retrying...", attempt, MAX_RETRY_ATTEMPTS);
                try {
                    Thread.sleep(1000 * attempt); // Exponential backoff
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new ConfigurationException("Configuration retrieval interrupted", ie);
                }
            }
        }

        // This should never be reached due to the throw in the last iteration
        throw new ConfigurationException("Unexpected error in configuration retrieval");
    }

    /**
     * Validates the initial configuration by attempting to fetch and parse it.
     *
     * @throws ConfigurationException if initial configuration is invalid or cannot be fetched
     */
    private void validateInitialConfiguration() {
        try {
            ConfigData initialConfig = this.getConfigData();
            if (initialConfig == null ||
                    initialConfig.generalConfig() == null ||
                    initialConfig.providerConfigs() == null) {
                throw new ConfigurationException("Invalid initial configuration: null values detected");
            }
            logger.info("Initial configuration validated successfully");
        } catch (Exception e) {
            logger.error("Failed to validate initial configuration", e);
            throw new ConfigurationException("Initial configuration validation failed", e);
        }
    }

    /**
     * Fetches fresh configurations with validation.
     *
     * @return ConfigData containing validated configurations
     * @throws ConfigurationException if configurations are invalid or cannot be fetched
     */
    private ConfigData fetchConfigurations() {
        logger.debug("Fetching fresh configurations from source");
        try {
            Map<String, String> configMap = configFetcher.getConfig();
            if (configMap == null || configMap.isEmpty()) {
                throw new ConfigurationException("Retrieved configuration map is null or empty");
            }
            GeneralConfig generalConfig = ProviderConfigParser.parseGeneralConfig(configMap);
            Map<String, ProviderConfig> providerConfigs = ProviderConfigParser.parseProviderConfigs(configMap);

            validateConfigurations(generalConfig, providerConfigs);

            logger.info("Successfully fetched and validated configurations for {} providers",
                    providerConfigs.size());

            return new ConfigData(generalConfig, providerConfigs);
        } catch (Exception e) {
            logger.error("Failed to fetch or parse configurations", e);
            throw new ConfigurationException("Failed to fetch or parse configurations", e);
        }
    }

    /**
     * Validates the fetched configurations.
     *
     * @param generalConfig   the general configuration
     * @param providerConfigs the provider-specific configurations
     * @throws ConfigurationException if configurations are invalid
     */
    private void validateConfigurations(GeneralConfig generalConfig,
                                        Map<String, ProviderConfig> providerConfigs) {
        if (generalConfig == null) {
            throw new ConfigurationException("General configuration is null");
        }
        if (providerConfigs == null || providerConfigs.isEmpty()) {
            throw new ConfigurationException("No provider configurations found");
        }
    }


    /**
     * Manually invalidates all cached configurations.
     */
    public void clearCache() {
        logger.info("Manually clearing configuration cache");
        configCache.invalidateAll();
        logger.debug("Configuration cache cleared successfully");
    }
}
