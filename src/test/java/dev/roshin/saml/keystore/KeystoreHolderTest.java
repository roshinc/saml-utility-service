package dev.roshin.saml.keystore;

import dev.roshin.saml.domain.CertificateInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class KeystoreHolderTest {

    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEY_ALIAS = "mykeyalias";
    private static Path keystorePath;

    @BeforeAll
    public static void setup() {
        URL keystoreUrl = KeystoreHolderTest.class.getClassLoader().getResource("test-keystore.jks");
        assertNotNull(keystoreUrl, "Keystore file not found in test resources");
        keystorePath = Paths.get(new File(keystoreUrl.getFile()).getAbsolutePath());
    }

    @Test
    public void testSuccessfulInitialization() throws Exception {
        KeystoreHolder keystoreObject = new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, KEY_ALIAS);

        assertAll("Keystore initialization",
                () -> assertNotNull(keystoreObject.getCredential(), "Credential should not be null"),
                () -> assertNotNull(keystoreObject.getCredential().getPrivateKey(), "Private key should not be null"),
                () -> assertNotNull(keystoreObject.getCredential().getEntityCertificate(), "Certificate should not be null"),
                () -> assertEquals(keystorePath, keystoreObject.getKeystorePath(), "Keystore path should match"),
                () -> assertEquals(KEY_ALIAS, keystoreObject.getKeyAlias(), "Key alias should match"),
                () -> assertNotNull(keystoreObject.getCertificate(), "Certificate retrieval should work")
        );
    }

    @Test
    public void testInvalidKeystorePath() {
        Path invalidPath = Paths.get("/invalid/path/to/keystore.jks");
        NoSuchFileException exception = assertThrows(NoSuchFileException.class,
                () -> new KeystoreHolder(invalidPath, KEYSTORE_PASSWORD, KEY_ALIAS)
        );
    }

    @Test
    public void testInvalidKeystorePassword() {
        String invalidPassword = "wrongpassword";
        IOException exception = assertThrows(IOException.class,
                () -> new KeystoreHolder(keystorePath, invalidPassword, KEY_ALIAS)
        );
        assertTrue(exception.getMessage().contains("keystore password was incorrect"));
    }

    @Test
    public void testInvalidAlias() {
        String invalidAlias = "wrongalias";
        Exception exception = assertThrows(Exception.class,
                () -> new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, invalidAlias)
        );
        assertTrue(exception.getMessage().contains("No private key found for alias"));
    }

    @Test
    public void testNullParameters() {
        assertAll("Null Parameters",
                () -> assertThrows(NullPointerException.class,
                        () -> new KeystoreHolder(null, KEYSTORE_PASSWORD, KEY_ALIAS)),
                () -> assertThrows(NullPointerException.class,
                        () -> new KeystoreHolder(keystorePath, null, KEY_ALIAS)),
                () -> assertThrows(NullPointerException.class,
                        () -> new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, null))
        );
    }

    @Test
    public void testToString() throws Exception {
        KeystoreHolder keystoreObject = new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, KEY_ALIAS);
        String toString = keystoreObject.toString();

        assertAll("ToString validation",
                () -> assertTrue(toString.contains(keystorePath.toString()), "Should contain keystore path"),
                () -> assertTrue(toString.contains(KEY_ALIAS), "Should contain alias"),
                () -> assertTrue(toString.contains("********"), "Should contain masked password"),
                () -> assertFalse(toString.contains(KEYSTORE_PASSWORD), "Should not contain actual password")
        );
    }

    @Test
    public void testMetadata() throws Exception {
        KeystoreHolder keystoreObject = new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, KEY_ALIAS);
        CertificateInfo metadata = keystoreObject.getMetadata();

        assertAll("Metadata validation",
                () -> assertNotNull(metadata, "Metadata should not be null"),
                () -> assertEquals(keystorePath.toString(), metadata.keystorePath(), "Should contain correct path"),
                () -> assertEquals(KEY_ALIAS, metadata.primaryAlias(), "Should contain correct alias"),
                () -> assertNotNull(metadata.certificates(), "Should contain certificates list"),
                () -> assertFalse(metadata.certificates().isEmpty(), "Should contain at least one certificate"),
                () -> {
                    var firstCert = metadata.certificates().get(0);
                    assertAll("Certificate metadata",
                            () -> assertNotNull(firstCert.alias(), "Should have alias"),
                            () -> assertNotNull(firstCert.subject(), "Should have subject"),
                            () -> assertNotNull(firstCert.issuer(), "Should have issuer"),
                            () -> assertNotNull(firstCert.validFrom(), "Should have validFrom"),
                            () -> assertNotNull(firstCert.validUntil(), "Should have validUntil"),
                            () -> assertNotNull(firstCert.serialNumber(), "Should have serialNumber")
                    );
                },
                () -> {
                    // Verify primary certificate is marked correctly
                    boolean hasPrimaryCert = metadata.certificates().stream()
                            .anyMatch(cert -> cert.isPrimary() && cert.alias().equals(KEY_ALIAS));
                    assertTrue(hasPrimaryCert, "Should have primary certificate marked");
                },
                () -> assertEquals("JKS", metadata.type(), "Should be JKS type"),
                () -> assertTrue(metadata.size() > 0, "Should have positive size")
        );

        // Print formatted metadata for debugging
        System.out.println("Keystore Metadata:");
        System.out.printf("Path: %s%n", metadata.keystorePath());
        System.out.printf("Name: %s%n", metadata.keystoreName());
        System.out.printf("Primary Alias: %s%n", metadata.primaryAlias());
        System.out.printf("Type: %s%n", metadata.type());
        System.out.printf("Size: %d%n", metadata.size());
        System.out.println("Certificates:");
        metadata.certificates().forEach(cert ->
                System.out.printf("""
                                
                                - Alias: %s
                                  Subject: %s
                                  Issuer: %s
                                  Serial: %s
                                  Valid From: %s
                                  Valid Until: %s
                                  Is Primary: %s
                                """,
                        cert.alias(),
                        cert.subject(),
                        cert.issuer(),
                        cert.serialNumber(),
                        cert.validFrom(),
                        cert.validUntil(),
                        cert.isPrimary()
                )
        );
    }

    @Test
    public void testCertificateRetrieval() throws Exception {
        KeystoreHolder keystoreObject = new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, KEY_ALIAS);
        X509Certificate cert = keystoreObject.getCertificate();

        assertAll("Certificate validation",
                () -> assertNotNull(cert, "Certificate should not be null"),
                () -> assertNotNull(cert.getSubjectX500Principal(), "Certificate should have subject"),
                () -> assertNotNull(cert.getIssuerX500Principal(), "Certificate should have issuer"),
                () -> assertTrue(cert.getNotAfter().after(cert.getNotBefore()),
                        "Certificate expiration should be after start date")
        );
    }

    @Test
    public void testKeystoreName() throws Exception {
        KeystoreHolder keystoreObject = new KeystoreHolder(keystorePath, KEYSTORE_PASSWORD, KEY_ALIAS);
        String keystoreName = keystoreObject.getKeystoreName();

        assertNotNull(keystoreName, "Keystore name should not be null");
        assertTrue(keystoreName.endsWith(".jks"), "Keystore name should have correct extension");
        assertEquals("test-keystore.jks", keystoreName, "Keystore name should match expected value");
    }
}