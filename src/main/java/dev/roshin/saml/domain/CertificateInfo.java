package dev.roshin.saml.domain;

import java.util.List;

public record CertificateInfo(
        String keystorePath,
        String keystoreName,
        String primaryAlias,
        String type,
        int size,
        List<CertificateDetails> certificates
) {
    public record CertificateDetails(
            String alias,
            String subject,
            String issuer,
            String serialNumber,
            String validFrom,
            String validUntil,
            boolean isPrimary
    ) {
    }
}