package dev.roshin.saml.services.config.fetcher;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import jakarta.enterprise.context.ApplicationScoped;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * Fetches configuration data via a REST call.
 */
@ApplicationScoped
public class RestConfigFetcher implements ConfigFetcher {

    private final HttpClient httpClient;
    private final Gson gson;
    private final String configUrl;

    /**
     * Constructs a new RestConfigFetcher.
     */
    public RestConfigFetcher() {
        this.httpClient = HttpClients.createDefault();
        this.gson = new Gson();

        Config config = ConfigProvider.getConfig();
        Optional<String> configUrlOpt = config.getOptionalValue("saml.config.endpoint.url", String.class);
        if (configUrlOpt.isEmpty()) {
            throw new IllegalStateException("Configuration property 'saml.config.endpoint.url' is not set");
        }
        this.configUrl = configUrlOpt.get();
    }

    @Override
    public Map<String, String> getConfig() {
        try {
            HttpGet request = new HttpGet(configUrl);
            String json = httpClient.execute(request, response ->
                    EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));

            Type type = new TypeToken<Map<String, String>>() {
            }.getType();
            return gson.fromJson(json, type);
        } catch (Exception e) {
            throw new RuntimeException("Error fetching configurations", e);
        }
    }
}
