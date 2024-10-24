package dev.roshin.saml.config;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.concurrent.TimeUnit;

public class SamlConfigurationFetcher {
    private static final Logger logger = LoggerFactory.getLogger(SamlConfigurationFetcher.class);
    private static final int CONNECT_TIMEOUT = 5000; // 5 seconds
    private static final int READ_TIMEOUT = 5000;    // 5 seconds

    /**
     * Fetches the SAML configuration from the specified endpoint URL.
     *
     * @param configEndpoint The complete URL of the configuration endpoint
     * @return The JSON configuration as a String
     * @throws RuntimeException if the fetch fails or returns invalid data
     */
    public static String fetchConfiguration(String configEndpoint) {
        try {
            logger.debug("Fetching SAML configuration from: {}", configEndpoint);

            ConfigurationService client = RestClientBuilder.newBuilder()
                    .baseUri(URI.create(configEndpoint))
                    .connectTimeout(CONNECT_TIMEOUT, TimeUnit.MILLISECONDS)
                    .readTimeout(READ_TIMEOUT, TimeUnit.MILLISECONDS)
                    .build(ConfigurationService.class);

            Response response = client.getConfiguration();

            if (response.getStatus() != 200) {
                String errorMsg = String.format("Failed to fetch SAML configuration. Status: %d", response.getStatus());
                logger.error(errorMsg);
                throw new RuntimeException(errorMsg);
            }

            String configuration = response.readEntity(String.class);

            if (configuration == null || configuration.trim().isEmpty()) {
                throw new RuntimeException("Received empty SAML configuration");
            }

            logger.debug("Successfully fetched SAML configuration");
            return configuration;

        } catch (ProcessingException e) {
            logger.error("Error connecting to SAML configuration endpoint: {}", configEndpoint, e);
            throw new RuntimeException("Failed to connect to SAML configuration service", e);
        } catch (Exception e) {
            logger.error("Unexpected error fetching SAML configuration from: {}", configEndpoint, e);
            throw new RuntimeException("Failed to fetch SAML configuration", e);
        }
    }

    @Path("/")
    interface ConfigurationService {
        @GET
        Response getConfiguration();
    }
}