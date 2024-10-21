package dev.roshin.saml.processing.util;

import dev.roshin.saml.processing.domain.IdentityInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SamlGeneratorTest {

    private static SamlGenerator samlGenerator;
    private static BasicX509Credential signingCredential;

    @BeforeAll
    static void setUp() throws Exception {

        // Add Security Provider BouncyCastle
        Security.addProvider(new BouncyCastleProvider());

        // Initialize OpenSAML
        InitializationService.initialize();

        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream is = SamlGeneratorTest.class.getResourceAsStream("/test-keystore.jks")) {
            keyStore.load(is, "changeit".toCharArray());
        }

        // Get the private key and certificate
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("mykeyalias", "changeit".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("mykeyalias");

        // Create the signing credential
        signingCredential = CredentialSupport.getSimpleCredential(certificate, privateKey);

        // Create SamlGenerator instance
        samlGenerator = new SamlGenerator();
    }

    @Test
    void testGenerateAndMarshalAssertion() throws Exception {
        // Create a sample IdentityInfo
        IdentityInfo identityInfo = new IdentityInfo();
        identityInfo.setUserId("testuser");
        identityInfo.setIssuer("https://test-issuer.com");
        identityInfo.addAttribute("email", "testuser@example.com");
        identityInfo.addAttribute("role", "user");

        // Generate the assertion
        Assertion assertion = samlGenerator.generateAssertion(identityInfo, signingCredential);

        // Verify the assertion
        assertNotNull(assertion);
        assertEquals("testuser", assertion.getSubject().getNameID().getValue());
        assertEquals("https://test-issuer.com", assertion.getIssuer().getValue());
        //Print the attributes
        for (Attribute attr : assertion.getAttributeStatements().get(0).getAttributes()) {
            System.out.println(attr.getName());
            // System.out.println(attr.getAttributeValues().get(0).getDOM().getTextContent());
        }
        assertEquals(4, assertion.getAttributeStatements().get(0).getAttributes().size());

        // Marshal the assertion
        String marshalledAssertion = samlGenerator.marshalAssertion(assertion);

        System.out.println(marshalledAssertion);

        byte[] encoded = Base64.getEncoder().encode(marshalledAssertion.getBytes());
        System.out.println("Encoded String: " + new String(encoded));

        // Verify the marshaled assertion
        assertNotNull(marshalledAssertion);
        assertTrue(marshalledAssertion.contains("saml2:Assertion"));
        assertTrue(marshalledAssertion.contains("testuser@example.com"));
        assertTrue(marshalledAssertion.contains("user"));
    }
}