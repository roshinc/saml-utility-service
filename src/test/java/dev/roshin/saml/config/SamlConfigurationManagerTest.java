package dev.roshin.saml.config;

import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SamlConfigurationManagerTest {

    private static final String VALID_CONFIG_JSON = """
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
    @Mock
    private Config config;
    @InjectMocks
    private SamlConfigurationManager configManager;

    @BeforeEach
    void setUp() throws Exception {
        // Mock MicroProfile Config injection
        when(config.getValue("saml.config.endpoint.url", String.class))
                .thenReturn("http://test-endpoint/config");
        when(config.getValue("saml.config.cache.refresh.seconds", Long.class))
                .thenReturn(-1L);

        // Use reflection to set the config values
        var endpointUrlField = SamlConfigurationManager.class.getDeclaredField("configEndpointUrl");
        endpointUrlField.setAccessible(true);
        endpointUrlField.set(configManager, "http://test-endpoint/config");

        var refreshSecondsField = SamlConfigurationManager.class.getDeclaredField("cacheRefreshSeconds");
        refreshSecondsField.setAccessible(true);
        refreshSecondsField.set(configManager, -1L);
    }

    @Nested
    class InitialLoadTests {
        @Test
        void shouldLoadConfigurationSuccessfully() {
            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher =
                         mockStatic(SamlConfigurationFetcher.class)) {

                mockedFetcher.when(() ->
                                SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .thenReturn(VALID_CONFIG_JSON);

                SamlConfiguration config = configManager.getConfiguration();

                assertNotNull(config);
                assertEquals("certs", config.getCertLibPath());
                assertEquals(Set.of("PROVIDER1", "PROVIDER2"), config.getProviderIds());

                // Verify PROVIDER1 config
                Optional<ProviderConfig> provider1 = config.getProvider("PROVIDER1");
                assertTrue(provider1.isPresent());
                assertEquals("provider1", provider1.get().getKeyAlias());
                assertEquals("provider1.jks", provider1.get().getKeystoreFile());

                // Verify fetch was called exactly once
                mockedFetcher.verify(() ->
                        SamlConfigurationFetcher.fetchConfiguration(anyString()), times(1));
            }
        }

        @Test
        void shouldThrowExceptionOnInvalidJson() {
            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher =
                         mockStatic(SamlConfigurationFetcher.class)) {

                mockedFetcher.when(() ->
                                SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .thenReturn("invalid json");

                assertThrows(RuntimeException.class, () ->
                        configManager.getConfiguration());
            }
        }

        @Test
        void shouldThrowExceptionWhenFetchFails() {
            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher =
                         mockStatic(SamlConfigurationFetcher.class)) {

                mockedFetcher.when(() ->
                                SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .thenThrow(new RuntimeException("Network error"));

                assertThrows(RuntimeException.class, () ->
                        configManager.getConfiguration());
            }
        }
    }

    @Nested
    class CacheRefreshTests {
        @BeforeEach
        void setUpRefresh() throws Exception {
            var refreshSecondsField = SamlConfigurationManager.class
                    .getDeclaredField("cacheRefreshSeconds");
            refreshSecondsField.setAccessible(true);
            refreshSecondsField.set(configManager, 1L); // 1 second refresh

            var lastRefreshField = SamlConfigurationManager.class
                    .getDeclaredField("lastRefresh");
            lastRefreshField.setAccessible(true);
            lastRefreshField.set(configManager, Instant.now().minusSeconds(2));
        }

        @Test
        void shouldRefreshWhenCacheExpired() {
            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher =
                         mockStatic(SamlConfigurationFetcher.class)) {

                mockedFetcher.when(() ->
                                SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .thenReturn(VALID_CONFIG_JSON);

                // First call
                configManager.getConfiguration();

                // Second call after cache expiration
                configManager.getConfiguration();

                // Verify fetched twice
                mockedFetcher.verify(() ->
                        SamlConfigurationFetcher.fetchConfiguration(anyString()), times(2));
            }
        }

        @Test
        void shouldNotRefreshWhenCacheValid() throws NoSuchFieldException, IllegalAccessException {
            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher =
                         mockStatic(SamlConfigurationFetcher.class)) {

                mockedFetcher.when(() ->
                                SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .thenReturn(VALID_CONFIG_JSON);

                // First call
                configManager.getConfiguration();

                // Update last refresh time to now
                var lastRefreshField = SamlConfigurationManager.class
                        .getDeclaredField("lastRefresh");
                lastRefreshField.setAccessible(true);
                lastRefreshField.set(configManager, Instant.now());

                // Second call with valid cache
                configManager.getConfiguration();

                // Verify fetched only once
                mockedFetcher.verify(() ->
                        SamlConfigurationFetcher.fetchConfiguration(anyString()), times(1));
            }
        }
    }

    @Nested
    class ThreadSafetyTests {
        @Test
        void shouldHandleConcurrentAccess() throws InterruptedException {
            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch completionLatch = new CountDownLatch(threadCount);
            AtomicInteger fetchCount = new AtomicInteger(0);

            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher = mockStatic(SamlConfigurationFetcher.class)) {
                // Setup the mock to count invocations
                mockedFetcher.when(() -> SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .then(invocation -> {
                            fetchCount.incrementAndGet();
                            return VALID_CONFIG_JSON;
                        });

                // Create and start threads
                ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
                List<Future<?>> futures = new ArrayList<>();

                // Submit tasks
                for (int i = 0; i < threadCount; i++) {
                    futures.add(executorService.submit(() -> {
                        try {
                            // Wait for all threads to be ready
                            startLatch.await();
                            // Get configuration
                            SamlConfiguration config = configManager.getConfiguration();
                            assertNotNull(config);
                            return null;
                        } finally {
                            completionLatch.countDown();
                        }
                    }));
                }

                // Start all threads simultaneously
                startLatch.countDown();

                // Wait for completion
                assertTrue(completionLatch.await(5, TimeUnit.SECONDS));

                // Shutdown executor and wait for all tasks to complete
                executorService.shutdown();
                assertTrue(executorService.awaitTermination(5, TimeUnit.SECONDS));

                // Check for any exceptions in the futures
                for (Future<?> future : futures) {
                    assertDoesNotThrow(() -> future.get());
                }

                // Verify the fetch count
                assertEquals(1, fetchCount.get(), "Configuration should be fetched exactly once");

                // Verify using Mockito
                mockedFetcher.verify(
                        () -> SamlConfigurationFetcher.fetchConfiguration(anyString()),
                        times(1)
                );
            }
        }

        @Test
        void shouldHandleConcurrentRefresh() throws InterruptedException {
            // Set up refresh interval
            try {
                var refreshSecondsField = SamlConfigurationManager.class.getDeclaredField("cacheRefreshSeconds");
                refreshSecondsField.setAccessible(true);
                refreshSecondsField.set(configManager, 1L); // 1 second refresh interval

                var lastRefreshField = SamlConfigurationManager.class.getDeclaredField("lastRefresh");
                lastRefreshField.setAccessible(true);
                lastRefreshField.set(configManager, Instant.now().minusSeconds(2)); // Force refresh
            } catch (Exception e) {
                fail("Failed to set up test conditions", e);
            }

            int threadCount = 10;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch completionLatch = new CountDownLatch(threadCount);
            AtomicInteger fetchCount = new AtomicInteger(0);

            try (MockedStatic<SamlConfigurationFetcher> mockedFetcher = mockStatic(SamlConfigurationFetcher.class)) {
                // Setup the mock with counting
                mockedFetcher.when(() -> SamlConfigurationFetcher.fetchConfiguration(anyString()))
                        .then(invocation -> {
                            fetchCount.incrementAndGet();
                            return VALID_CONFIG_JSON;
                        });

                ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
                List<Future<?>> futures = new ArrayList<>();

                // Submit tasks
                for (int i = 0; i < threadCount; i++) {
                    futures.add(executorService.submit(() -> {
                        try {
                            startLatch.await();
                            SamlConfiguration config = configManager.getConfiguration();
                            assertNotNull(config);
                            return null;
                        } finally {
                            completionLatch.countDown();
                        }
                    }));
                }

                // Start all threads simultaneously
                startLatch.countDown();

                // Wait for completion
                assertTrue(completionLatch.await(5, TimeUnit.SECONDS));

                // Shutdown executor and wait for all tasks to complete
                executorService.shutdown();
                assertTrue(executorService.awaitTermination(5, TimeUnit.SECONDS));

                // Check for any exceptions in the futures
                for (Future<?> future : futures) {
                    assertDoesNotThrow(() -> future.get());
                }

                // Verify the fetch count
                assertEquals(1, fetchCount.get(), "Configuration should be fetched exactly once even during refresh");

                // Verify using Mockito
                mockedFetcher.verify(
                        () -> SamlConfigurationFetcher.fetchConfiguration(anyString()),
                        times(1)
                );
            }
        }
    }
}