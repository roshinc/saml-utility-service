package dev.roshin.saml.rest.resources.certificates;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import dev.roshin.saml.certifcates.keystore.KeystoreHolder;
import dev.roshin.saml.config.ProviderConfig;
import dev.roshin.saml.config.SamlConfigurationManager;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class CertificateInfoService {
    private static final Logger logger = LoggerFactory.getLogger(CertificateInfoService.class);
    private final SamlConfigurationManager config;
    private final Map<String, KeystoreHolder> keystoreCache;

    @Inject
    public CertificateInfoService(SamlConfigurationManager config) {
        this.config = config;
        this.keystoreCache = new ConcurrentHashMap<>();
        initializeKeystores();
    }

    private void initializeKeystores() {
        for (String provider : config.getConfiguration().getProviderIds()) {
            try {
                Optional<ProviderConfig> providerConfigOptional = config.getConfiguration().getProvider(provider);
                if (providerConfigOptional.isEmpty()) {
                    logger.error("Provider configuration not found for provider: {}", provider);
                    continue;
                }

                ProviderConfig providerConfig = providerConfigOptional.get();
                Path keystorePath = Paths.get(config.getConfiguration().getCertLibPath(), providerConfig.getKeystoreFile());

                KeystoreHolder keystoreHolder = new KeystoreHolder(
                        keystorePath,
                        providerConfig.getKeystorePassword(),
                        providerConfig.getKeyAlias()
                );

                keystoreCache.put(provider, keystoreHolder);
                logger.info("Initialized keystore for provider: {}", provider);
            } catch (Exception e) {
                logger.error("Failed to initialize keystore for provider: {}", provider, e);
            }
        }
    }

    public JsonObject getAllCertificateInfo() {
        JsonObject response = new JsonObject();
        JsonArray providersInfo = new JsonArray();

        for (String provider : config.getConfiguration().getProviderIds()) {
            try {
                KeystoreHolder keystoreHolder = keystoreCache.get(provider);
                if (keystoreHolder != null) {
                    JsonObject providerInfo = keystoreHolder.getMetadata();
                    providerInfo.addProperty("providerId", provider);
                    providersInfo.add(providerInfo);
                } else {
                    JsonObject errorInfo = new JsonObject();
                    errorInfo.addProperty("providerId", provider);
                    errorInfo.addProperty("error", "Keystore not initialized");
                    providersInfo.add(errorInfo);
                }
            } catch (Exception e) {
                logger.error("Error getting certificate info for provider: {}", provider, e);
                JsonObject errorInfo = new JsonObject();
                errorInfo.addProperty("providerId", provider);
                errorInfo.addProperty("error", e.getMessage());
                providersInfo.add(errorInfo);
            }
        }

        response.addProperty("totalProviders", config.getConfiguration().getProviderIds().size());
        response.add("providers", providersInfo);
        return response;
    }
}