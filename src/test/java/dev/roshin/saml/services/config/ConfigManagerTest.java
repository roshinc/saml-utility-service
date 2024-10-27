package dev.roshin.saml.services.config;

import dev.roshin.saml.services.config.fetcher.ConfigFetcher;
import dev.roshin.saml.services.config.records.ConfigData;
import dev.roshin.saml.services.config.records.GeneralConfig;
import dev.roshin.saml.services.config.records.ProviderConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class ConfigManagerTest {

    private ConfigManager configManager;
    private ConfigFetcher mockConfigFetcher;
    private Optional<Long> cacheRefreshSecondsOpt;

    @BeforeEach
    public void setUp() {
        mockConfigFetcher = mock(ConfigFetcher.class);
        Map<String, String> mockConfigMap = Map.of(
                "CERT_LIB_PATH", "certs",
                "PROVIDER_LIST", "PROVIDER1, PROVIDER2",
                "PROVIDER1_KEYALIAS", "provider1",
                "PROVIDER1_KEYSTOREFILE", "provider1.jks",
                "PROVIDER1_KEYSTOREPASSWORD", "provider1",
                "PROVIDER1_PARSEENCODING", "provider1",
                "PROVIDER2_KEYALIAS", "provider2",
                "PROVIDER2_KEYSTOREFILE", "provider2.jks",
                "PROVIDER2_KEYSTOREPASSWORD", "provider2",
                "PROVIDER2_PARSEENCODING", "provider2"
        );
        when(mockConfigFetcher.getConfig()).thenReturn(mockConfigMap);

        cacheRefreshSecondsOpt = Optional.empty();

        configManager = new ConfigManager();
        configManager.configFetcher = mockConfigFetcher;
        configManager.init();
    }

    @Test
    public void testGetProviderConfigs_CacheBehavior() {

        // First call - should fetch from ConfigFetcher
        Map<String, ProviderConfig> configs1 = configManager.getConfigData().providerConfigs();
        verify(mockConfigFetcher, times(1)).getConfig();

        // Second call - should get from cache, not call ConfigFetcher again
        Map<String, ProviderConfig> configs2 = configManager.getConfigData().providerConfigs();
        verifyNoMoreInteractions(mockConfigFetcher);

        assertSame(configs1, configs2);

        // Now clear the cache
        configManager.clearCache();

        // Next call should fetch from ConfigFetcher again
        Map<String, ProviderConfig> configs3 = configManager.getConfigData().providerConfigs();
        verify(mockConfigFetcher, times(2)).getConfig();

        // configs3 should be a new object
        assertNotSame(configs1, configs3);
    }

    @Test
    public void testGetConfigData() {
        ConfigData configData = configManager.getConfigData();
        assertNotNull(configData);

        // Test GeneralConfig
        GeneralConfig generalConfig = configData.generalConfig();
        assertNotNull(generalConfig);
        assertEquals("certs", generalConfig.certLibPath());

        // Test ProviderConfigs
        Map<String, ProviderConfig> providerConfigs = configData.providerConfigs();
        assertNotNull(providerConfigs);
        assertEquals(2, providerConfigs.size());

        ProviderConfig provider1Config = providerConfigs.get("PROVIDER1");
        assertNotNull(provider1Config);
        assertEquals("provider1", provider1Config.keyAlias());
        assertEquals("provider1.jks", provider1Config.keystoreFile());

        ProviderConfig provider2Config = providerConfigs.get("PROVIDER2");
        assertNotNull(provider2Config);
        assertEquals("provider2", provider2Config.keyAlias());
        assertEquals("provider2.jks", provider2Config.keystoreFile());
    }
}
