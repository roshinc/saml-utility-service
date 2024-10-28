package dev.roshin.saml.rest.resources.response;

import dev.roshin.saml.domain.CertificateInfo;

import java.time.Instant;

public record KeystoreMetadata(
        CertificateInfo certificateInfo,
        String provider,
        String parseEncoding,
        Instant processedAt,
        KeystoreStatus status,
        String errorMessage
) {
    public static KeystoreMetadata success(CertificateInfo certInfo, String provider, String parseEncoding) {
        return new KeystoreMetadata(
                certInfo,
                provider,
                parseEncoding,
                Instant.now(),
                KeystoreStatus.SUCCESS,
                null
        );
    }

    public static KeystoreMetadata failure(String provider, String errorMessage) {
        return new KeystoreMetadata(
                null,
                provider,
                null,
                Instant.now(),
                KeystoreStatus.FAILURE,
                errorMessage
        );
    }
}