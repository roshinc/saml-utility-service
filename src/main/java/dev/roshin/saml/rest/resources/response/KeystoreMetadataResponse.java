package dev.roshin.saml.rest.resources.response;

import com.google.gson.JsonObject;

import java.util.Map;

public record KeystoreMetadataResponse(
        Map<String, JsonObject> providersMetadata,
        String timestamp,
        int totalProviders,
        boolean success,
        String error
) {
    public static KeystoreMetadataResponse success(Map<String, JsonObject> metadata, String timestamp) {
        return new KeystoreMetadataResponse(
                metadata,
                timestamp,
                metadata.size(),
                true,
                null
        );
    }

    public static KeystoreMetadataResponse error(String errorMessage) {
        return new KeystoreMetadataResponse(
                null,
                null,
                0,
                false,
                errorMessage
        );
    }
}