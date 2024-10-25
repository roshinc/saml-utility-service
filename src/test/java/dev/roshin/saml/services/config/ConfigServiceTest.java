package dev.roshin.saml.services.config;

import dev.roshin.saml.test_utils.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

public class ConfigServiceTest {

    private ConfigService configService;
    private ConfigFetcher mockFetcher;
    private MutableClock mutableClock;

    @BeforeEach
    public void setup() {
        mockFetcher = Mockito.mock(ConfigFetcher.class);
        mutableClock = new MutableClock(Instant.now(), ZoneOffset.UTC);

        long cacheRefreshInterval = 60; // 60 seconds for testing

        // Set up default response for fetchConfig()
        String defaultJsonResponse = """
                {
                  "CERT_LIB_PATH": "certs",
                  "PROVIDER_LIST": "PROVIDER1, PROVIDER2",
                  "PROVIDER1_KEYALIAS": "provider1",
                  "PROVIDER1_KEYSTOREFILE": "provider1.jks",
                  "PROVIDER1_KEYSTOREPASSWORD": "provider1",
                  "PROVIDER1_PARSEENCODING": "provider1",
                  "PROVIDER2_KEYALIAS": "provider2",
                  "PROVIDER2_KEYSTOREFILE": "provider2.jks",
                  "PROVIDER2_KEYSTOREPASSWORD": "provider2",
                  "PROVIDER2_PARSEENCODING": "provider2"
                }
                """;
        when(mockFetcher.fetchConfig()).thenReturn(defaultJsonResponse);

        configService = new ConfigService();
        // Set the injected fields directly
        configService.configFetcher = mockFetcher;
        configService.cacheRefreshInterval = cacheRefreshInterval;
        configService.clock = mutableClock;
        configService.init();
    }

    @Test
    public void testConfigParsing() {

        ConfigService.ConfigData configData = configService.getConfigData();


        assertEquals("certs", configData.certLibPath());
        assertEquals(List.of("PROVIDER1", "PROVIDER2"), configData.providerList());

        ConfigService.ProviderConfig provider1 = configData.providerConfigs().get("PROVIDER1");
        assertEquals("provider1", provider1.keyAlias());
        assertEquals("provider1.jks", provider1.keystoreFile());
        assertEquals("provider1", provider1.keystorePassword());
        assertEquals("provider1", provider1.parseEncoding());

        ConfigService.ProviderConfig provider2 = configData.providerConfigs().get("PROVIDER2");
        assertEquals("provider2", provider2.keyAlias());
        assertEquals("provider2.jks", provider2.keystoreFile());
        assertEquals("provider2", provider2.keystorePassword());
        assertEquals("provider2", provider2.parseEncoding());
    }

    @Test
    public void testCacheRefresh() {
        String initialResponse = "{ \"CERT_LIB_PATH\": \"certs\", \"PROVIDER_LIST\": \"PROVIDER1\" }";
        String updatedResponse = "{ \"CERT_LIB_PATH\": \"new_certs\", \"PROVIDER_LIST\": \"PROVIDER2\" }";

        // Adjust the mock to return different responses
        when(mockFetcher.fetchConfig())
                .thenReturn(initialResponse) // For initial call
                .thenReturn(updatedResponse); // For refresh

        // First call should use initial response
        configService.refreshConfig(); // Ensure we get the initial response
        ConfigService.ConfigData initialData = configService.getConfigData();
        assertEquals("certs", initialData.certLibPath());

        // Advance clock beyond cache refresh interval
        mutableClock.advance(Duration.ofSeconds(61));

        // Second call should trigger a refresh and use updated response
        ConfigService.ConfigData refreshedData = configService.getConfigData();
        assertEquals("new_certs", refreshedData.certLibPath());

        verify(mockFetcher, times(3)).fetchConfig();
    }
}