package dev.roshin.saml.rest.resources;

import dev.roshin.saml.keystore.KeystoreHolder;
import dev.roshin.saml.rest.resources.response.ErrorResponse;
import dev.roshin.saml.rest.resources.response.KeystoreMetadata;
import dev.roshin.saml.rest.resources.response.KeystoreOperationResponse;
import dev.roshin.saml.rest.resources.response.KeystoreStatus;
import dev.roshin.saml.services.config.ConfigManager;
import dev.roshin.saml.services.config.records.ConfigData;
import dev.roshin.saml.services.config.records.ProviderConfig;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Path("/keystores")
@RequestScoped
public class KeystoreResource {
    private static final Logger logger = LoggerFactory.getLogger(KeystoreResource.class);
    private static final int TIMEOUT_SECONDS = 30;

    @Inject
    private ConfigManager configManager;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getKeystoresMetadata() {
        String operationId = UUID.randomUUID().toString();
        logger.info("Starting keystore metadata retrieval operation: {}", operationId);

        try {
            ConfigData configData = configManager.getConfigData();
            Map<String, ProviderConfig> providerConfigs = configData.providerConfigs();

            // Use ConcurrentHashMap for thread-safe results collection
            Map<String, KeystoreMetadata> results = new ConcurrentHashMap<>();

            // Create a thread pool for parallel processing
            try (ExecutorService executorService = Executors.newFixedThreadPool(
                    Math.min(providerConfigs.size(), Runtime.getRuntime().availableProcessors()))) {

                // Submit tasks for each provider
                for (Map.Entry<String, ProviderConfig> entry : providerConfigs.entrySet()) {
                    String providerName = entry.getKey();
                    ProviderConfig config = entry.getValue();

                    executorService.submit(() -> processProvider(providerName, config, results));
                }

                // Shutdown and wait for completion
                executorService.shutdown();
                if (!executorService.awaitTermination(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    logger.error("Operation {} timed out after {} seconds", operationId, TIMEOUT_SECONDS);
                    executorService.shutdownNow();
                    return createTimeoutResponse(operationId, results);
                }
            }

            return createSuccessResponse(operationId, results);

        } catch (Exception e) {
            logger.error("Operation {} failed with unexpected error", operationId, e);
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse(
                            "Failed to process keystores: " + e.getMessage(),
                            operationId,
                            Instant.now(),
                            e.getClass().getSimpleName()
                    ))
                    .build();
        }
    }

    private void processProvider(String providerName, ProviderConfig config,
                                 Map<String, KeystoreMetadata> results) {
        logger.debug("Processing provider: {}", providerName);
        try {
            validateProviderConfig(config);

            KeystoreHolder keystoreHolder = new KeystoreHolder(
                    Paths.get(configManager.getConfigData().generalConfig().certLibPath(), config.keystoreFile()),
                    config.keystorePassword(),
                    config.keyAlias()
            );

            results.put(providerName, KeystoreMetadata.success(
                    keystoreHolder.getMetadata(),
                    providerName,
                    config.parseEncoding()
            ));

            logger.info("Successfully processed keystore for provider: {}", providerName);

        } catch (Exception e) {
            logger.error("Failed to process provider {}: {}", providerName, e.getMessage(), e);
            results.put(providerName, KeystoreMetadata.failure(
                    providerName,
                    String.format("Failed to process keystore: %s - %s", e.getClass().getSimpleName(), e.getMessage())
            ));
        }
    }

    private void validateProviderConfig(ProviderConfig config) {
        if (config.keystoreFile() == null || config.keystoreFile().isEmpty()) {
            throw new IllegalArgumentException("Keystore file path is missing");
        }
        if (config.keystorePassword() == null || config.keystorePassword().isEmpty()) {
            throw new IllegalArgumentException("Keystore password is missing");
        }
        if (config.keyAlias() == null || config.keyAlias().isEmpty()) {
            throw new IllegalArgumentException("Key alias is missing");
        }
    }

    private Response createTimeoutResponse(String operationId, Map<String, KeystoreMetadata> partialResults) {
        int successCount = countSuccesses(partialResults);

        return Response
                .status(Response.Status.GATEWAY_TIMEOUT)
                .entity(new KeystoreOperationResponse(
                        partialResults,
                        new KeystoreOperationResponse.OperationSummary(
                                partialResults.size(),
                                successCount,
                                partialResults.size() - successCount,
                                true,
                                operationId
                        ),
                        Instant.now()
                ))
                .build();
    }

    private Response createSuccessResponse(String operationId, Map<String, KeystoreMetadata> results) {
        int successCount = countSuccesses(results);
        boolean hasErrors = successCount < results.size();

        return new KeystoreOperationResponse(
                results,
                new KeystoreOperationResponse.OperationSummary(
                        results.size(),
                        successCount,
                        results.size() - successCount,
                        hasErrors,
                        operationId
                ),
                Instant.now()
        ).toResponse();
    }

    private int countSuccesses(Map<String, KeystoreMetadata> results) {
        return (int) results.values().stream()
                .filter(metadata -> metadata.status() == KeystoreStatus.SUCCESS)
                .count();
    }
}