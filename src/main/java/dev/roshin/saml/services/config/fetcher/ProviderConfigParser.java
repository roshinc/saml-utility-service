package dev.roshin.saml.services.config.fetcher;

import dev.roshin.saml.services.config.records.GeneralConfig;
import dev.roshin.saml.services.config.records.ProviderConfig;

import java.util.HashMap;
import java.util.Map;

/**
 * Parses raw configuration maps into ProviderConfig instances.
 */
public class ProviderConfigParser {

    /**
     * Parses the general configurations.
     *
     * @param configMap The raw configuration map.
     * @return A GeneralConfig instance.
     */
    public static GeneralConfig parseGeneralConfig(Map<String, String> configMap) {
        String certLibPath = configMap.get("CERT_LIB_PATH");
        return new GeneralConfig(certLibPath);
    }


    /**
     * Parses the configurations into a map of ProviderConfig instances.
     *
     * @param configMap The raw configuration map.
     * @return A map of provider names to ProviderConfig instances.
     */
    public static Map<String, ProviderConfig> parseProviderConfigs(Map<String, String> configMap) {
        Map<String, ProviderConfig> providerConfigs = new HashMap<>();
        String providerListStr = configMap.get("PROVIDER_LIST");

        if (providerListStr != null) {
            String[] providers = providerListStr.split(",\\s*");
            for (String provider : providers) {
                String keyAlias = configMap.get(provider + "_KEYALIAS");
                String keystoreFile = configMap.get(provider + "_KEYSTOREFILE");
                String keystorePassword = configMap.get(provider + "_KEYSTOREPASSWORD");
                String parseEncoding = configMap.get(provider + "_PARSEENCODING");

                ProviderConfig providerConfig = new ProviderConfig(
                        keyAlias,
                        keystoreFile,
                        keystorePassword,
                        parseEncoding
                );
                providerConfigs.put(provider, providerConfig);
            }
        }
        return providerConfigs;
    }
}
