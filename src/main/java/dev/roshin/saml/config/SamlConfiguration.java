package dev.roshin.saml.config;

import com.google.gson.JsonObject;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class SamlConfiguration {
    private final String certLibPath;
    private final Set<String> providerIds;
    private final Map<String, ProviderConfig> providers;

    private SamlConfiguration(String certLibPath, Set<String> providerIds,
                              Map<String, ProviderConfig> providers) {
        this.certLibPath = certLibPath;
        this.providerIds = Set.copyOf(providerIds);
        this.providers = Map.copyOf(providers);
    }

    public static SamlConfiguration fromJson(JsonObject json) {
        String certLibPath = json.get("CERT_LIB_PATH").getAsString();
        Set<String> providerIds = Arrays.stream(
                        json.get("PROVIDER_LIST").getAsString().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());

        Map<String, ProviderConfig> providers = new ConcurrentHashMap<>();
        for (String providerId : providerIds) {
            providers.put(providerId, new ProviderConfig(
                    json.get(providerId + "_KEYALIAS").getAsString(),
                    json.get(providerId + "_KEYSTOREFILE").getAsString(),
                    json.get(providerId + "_KEYSTOREPASSWORD").getAsString(),
                    json.get(providerId + "_PARSEENCODING").getAsString()
            ));
        }

        return new SamlConfiguration(certLibPath, providerIds, providers);
    }

    public String getCertLibPath() {
        return certLibPath;
    }

    public Set<String> getProviderIds() {
        return providerIds;
    }

    public Optional<ProviderConfig> getProvider(String providerId) {
        return Optional.ofNullable(providers.get(providerId));
    }

    public Map<String, ProviderConfig> getProviders() {
        return providers;
    }
}
