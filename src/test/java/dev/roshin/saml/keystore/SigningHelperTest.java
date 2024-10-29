package dev.roshin.saml.keystore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.*;

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SigningHelperTest {

    private static XMLObjectBuilderFactory builderFactory;

    @BeforeAll
    public static void setUp() throws Exception {
        // Add Security Provider BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        // Initialize the OpenSAML library
        InitializationService.initialize();
        builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    }

    @Test
    public void testSignAssertion() throws Exception {
        // Load the keystore from the classpath
        URL keystoreUrl = getClass().getClassLoader().getResource("test-keystore.jks");
        assertNotNull(keystoreUrl, "Keystore file not found in resources.");

        Path keystorePath = Paths.get(new File(keystoreUrl.toURI()).getAbsolutePath());
        String keystorePassword = "changeit";
        String keyAlias = "mykeyalias";

        KeystoreHolder keystoreHolder = new KeystoreHolder(keystorePath, keystorePassword, keyAlias);

        SigningHelper signingHelper = new SigningHelper(keystoreHolder);

        // Create a SAML Assertion
        Assertion assertion = buildAssertion();

        // Sign the Assertion
        signingHelper.signAssertion(assertion);

        // Verify that the Assertion is signed
        assertTrue(signingHelper.isSigned(assertion), "Assertion should be signed.");

        // Serialize and print the signed assertion
        // String xmlString = XMLObjectSupport.marshallToString(assertion);
        // System.out.println(xmlString);
    }

    @Test
    public void testSignResponse() throws Exception {
        // Load the keystore from the classpath
        URL keystoreUrl = getClass().getClassLoader().getResource("test-keystore.jks");
        assertNotNull(keystoreUrl, "Keystore file not found in resources.");

        Path keystorePath = Paths.get(new File(keystoreUrl.toURI()).getAbsolutePath());
        String keystorePassword = "changeit";
        String keyAlias = "mykeyalias";

        KeystoreHolder keystoreHolder = new KeystoreHolder(keystorePath, keystorePassword, keyAlias);

        SigningHelper signingHelper = new SigningHelper(keystoreHolder);

        // Create a SAML Response
        Response response = buildResponse();

        // Sign the Response
        signingHelper.signResponse(response);

        // Verify that the Response is signed
        assertTrue(signingHelper.isSigned(response), "Response should be signed.");

        // Optionally, serialize and print the signed response
        // String xmlString = XMLObjectSupport.marshallToString(response);
        // System.out.println(xmlString);
    }

    private Assertion buildAssertion() {
        // Build the Assertion object
        Assertion assertion = (Assertion) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
                .buildObject(Assertion.DEFAULT_ELEMENT_NAME);

        // Set required attributes
        assertion.setID("_" + java.util.UUID.randomUUID().toString());
        assertion.setIssueInstant(Instant.now());

        // Set Issuer
        Issuer issuer = (Issuer) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
                .buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue("https://issuer.example.com");
        assertion.setIssuer(issuer);

        // Add Subject, Conditions, and other elements as needed
        // For simplicity, we'll keep it minimal

        return assertion;
    }

    private Response buildResponse() {
        // Build the Response object
        Response response = (Response) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME)
                .buildObject(Response.DEFAULT_ELEMENT_NAME);

        // Set required attributes
        response.setID("_" + java.util.UUID.randomUUID().toString());
        response.setIssueInstant(Instant.now());

        // Set Issuer
        Issuer issuer = (Issuer) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
                .buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue("https://issuer.example.com");
        response.setIssuer(issuer);

        // Set Status
        Status status = (Status) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME)
                .buildObject(Status.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = (StatusCode) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)
                .buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);

        // Optionally, add Assertions to the Response
        // For example:
        // Assertion assertion = buildAssertion();
        // response.getAssertions().add(assertion);

        return response;
    }
}