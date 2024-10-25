package dev.roshin.saml.services.config;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

@ApplicationScoped
public class ConfigService {

    private static final Logger logger = LoggerFactory.getLogger(ConfigService.class);

    private final ReentrantLock lock = new ReentrantLock();
    @Inject
    protected ConfigFetcher configFetcher;
    @Inject
    @ConfigProperty(name = "CACHE_REFRESH", defaultValue = "0")
    protected long cacheRefreshInterval;
    @Inject
    protected Clock clock;
    private ConfigData configData;
    private Instant lastUpdated;

    // Public no-args constructor required for proxying
    public ConfigService() {
    }

    @PostConstruct
    public void init() {
        refreshConfig();
    }

    public ConfigData getConfigData() {
        checkAndRefreshConfig();
        return configData;
    }

    private void checkAndRefreshConfig() {
        if (cacheRefreshInterval > 0) {
            Instant now = Instant.now(clock);
            if (Duration.between(lastUpdated, now).getSeconds() > cacheRefreshInterval) {
                refreshConfig();
            }
        }
    }

    protected void refreshConfig() {
        lock.lock();
        try {
            logger.debug("Refreshing configuration data");
            String jsonResponse = configFetcher.fetchConfig();
            this.configData = parseConfigData(jsonResponse);
            this.lastUpdated = Instant.now(clock);
            logger.debug("Configuration data refreshed at {}", lastUpdated);
        } finally {
            lock.unlock();
        }
    }

    private ConfigData parseConfigData(String jsonResponse) {
        Map<String, String> configMap = parseJsonToMap(jsonResponse);

        String certLibPath = configMap.get("CERT_LIB_PATH");
        String providerListStr = configMap.get("PROVIDER_LIST");
        List<String> providerList = Arrays.stream(providerListStr.split(","))
                .map(String::trim)
                .toList();

        Map<String, ProviderConfig> providerConfigs = new HashMap<>();
        for (String provider : providerList) {
            String keyAlias = configMap.get(provider + "_KEYALIAS");
            String keystoreFile = configMap.get(provider + "_KEYSTOREFILE");
            String keystorePassword = configMap.get(provider + "_KEYSTOREPASSWORD");
            String parseEncoding = configMap.get(provider + "_PARSEENCODING");

            ProviderConfig providerConfig = new ProviderConfig(keyAlias, keystoreFile, keystorePassword, parseEncoding);
            providerConfigs.put(provider, providerConfig);
        }

        return new ConfigData(certLibPath, providerList, providerConfigs);
    }

    private Map<String, String> parseJsonToMap(String jsonResponse) {
        return JsonUtils.parseJson(jsonResponse);
    }

    // Inner classes representing configuration data

    public record ConfigData(String certLibPath,
                             List<String> providerList,
                             Map<String, ProviderConfig> providerConfigs) {
    }

    public record ProviderConfig(String keyAlias,
                                 String keystoreFile,
                                 String keystorePassword,
                                 String parseEncoding) {
    }
}
