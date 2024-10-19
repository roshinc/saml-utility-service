package dev.roshin.saml.processing.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.security.x509.BasicX509Credential;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for KeystoreUtil.
 */
public class KeystoreUtilTest {

    // Variables for keystore path, password, and alias
    private static final String keystorePassword = "changeit";
    private static final String keyAlias = "mykeyalias";

    private static String keystorePath;

    /**
     * Initializes the keystore path before all tests.
     */
    @BeforeAll
    public static void setup() {
        // Load the keystore file from the test resources
        URL keystoreUrl = KeystoreUtilTest.class.getClassLoader().getResource("test-keystore.jks");
        assertNotNull(keystoreUrl, "Keystore file not found in test resources");
        keystorePath = new File(keystoreUrl.getFile()).getAbsolutePath();
    }

    /**
     * Tests successful loading of the credential.
     */
    @Test
    public void testInit_Success() {
        try {
            BasicX509Credential credential = KeystoreUtil.init(keystorePath, keystorePassword, keyAlias);
            assertNotNull(credential, "Credential should not be null");
            assertNotNull(credential.getPrivateKey(), "Private key should not be null");
            assertNotNull(credential.getEntityCertificate(), "Certificate should not be null");
        } catch (Exception e) {
            fail("Exception should not be thrown for valid keystore and alias: " + e.getMessage());
        }
    }

    /**
     * Tests behavior when an invalid keystore path is provided.
     */
    @Test
    public void testInit_InvalidKeystorePath() {
        String invalidPath = "/invalid/path/to/keystore.jks";
        FileNotFoundException exception = assertThrows(FileNotFoundException.class, () -> {
            KeystoreUtil.init(invalidPath, keystorePassword, keyAlias);
        });
        assertTrue(exception.getMessage().contains("(The system cannot find the path specified)"));
    }

    /**
     * Tests behavior when an incorrect keystore password is provided.
     */
    @Test
    public void testInit_InvalidKeystorePassword() {
        String invalidPassword = "wrongpassword";
        IOException exception = assertThrows(IOException.class, () -> {
            KeystoreUtil.init(keystorePath, invalidPassword, keyAlias);
        });
        assertTrue(exception.getMessage().contains("keystore password was incorrect"));
    }

    /**
     * Tests behavior when an incorrect alias is provided.
     */
    @Test
    public void testInit_InvalidAlias() {
        String invalidAlias = "wrongalias";
        Exception exception = assertThrows(Exception.class, () -> {
            KeystoreUtil.init(keystorePath, keystorePassword, invalidAlias);
        });
        assertTrue(exception.getMessage().contains("No private key found for alias"));
    }

    /**
     * Tests behavior when null parameters are passed.
     */
    @Test
    public void testInit_NullParameters() {
        assertAll("Null Parameters",
                () -> assertThrows(NullPointerException.class, () -> {
                    KeystoreUtil.init(null, keystorePassword, keyAlias);
                }),
                () -> assertThrows(NullPointerException.class, () -> {
                    KeystoreUtil.init(keystorePath, null, keyAlias);
                }),
                () -> assertThrows(NullPointerException.class, () -> {
                    KeystoreUtil.init(keystorePath, keystorePassword, null);
                })
        );
    }
}
