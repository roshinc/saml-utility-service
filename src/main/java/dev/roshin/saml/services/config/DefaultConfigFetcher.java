package dev.roshin.saml.services.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@ApplicationScoped
public class DefaultConfigFetcher implements ConfigFetcher {

    private final CloseableHttpClient httpClient;
    @Inject
    @ConfigProperty(name = "saml.config.endpoint.url", defaultValue = "0")
    private String CONFIG_URL;

    public DefaultConfigFetcher() {
        this.httpClient = HttpClients.createDefault();
    }

    @Override
    public String fetchConfig() {
        HttpGet request = new HttpGet(CONFIG_URL);

        try (CloseableHttpResponse response = httpClient.execute(request)) {
            int statusCode = response.getCode();

            if (statusCode == HttpStatus.SC_OK) {
                return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } else {
                throw new RuntimeException("Failed to fetch config. Status code: " + statusCode);
            }
        } catch (IOException e) {
            throw new RuntimeException("Error fetching config", e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    // Clean up resources when the application context is destroyed
    public void destroy() {
        try {
            if (httpClient != null) {
                httpClient.close();
            }
        } catch (IOException e) {
            // Log the error but don't throw as this is cleanup code
            e.printStackTrace();
        }
    }
}
