package dev.roshin.saml.processing.util;


import dev.roshin.saml.processing.domain.Authorization;
import dev.roshin.saml.processing.domain.IdentityInfo;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class SamlParser {
    private static final Logger logger = LoggerFactory.getLogger(SamlParser.class);

    /**
     * Constructor for SamlParser. Initializes OpenSAML library.
     *
     * @throws InitializationException if OpenSAML initialization fails
     */
    public SamlParser() throws InitializationException {
        InitializationService.initialize();
        logger.info("SamlParser initialized");
    }

    /**
     * Parses a SAML assertion string and returns an IdentityInfo object.
     *
     * @param assertionString the SAML assertion as a String
     * @param credential      the X.509 credential for signature validation
     * @return IdentityInfo object containing parsed assertion data
     * @throws SamlParserException if parsing or validation fails
     */
    public IdentityInfo parseAssertion(String assertionString, BasicX509Credential credential) throws SamlParserException {
        try {
            Assertion assertion = unmarshallAssertion(assertionString);
            validateAssertion(assertion, credential);
            return extractIdentityInfo(assertion);
        } catch (Exception e) {
            logger.error("Failed to parse SAML assertion", e);
            throw new SamlParserException("Failed to parse SAML assertion", e);
        }
    }

    /**
     * Validates a SAML assertion.
     *
     * @param assertion  the SAML assertion object
     * @param credential the X.509 credential for signature validation
     * @throws SamlParserException if validation fails
     */
    public void validateAssertion(Assertion assertion, BasicX509Credential credential) throws SamlParserException {
        validateSignature(assertion, credential);
        validateConditions(assertion);
        validateSubject(assertion);
    }

    private Assertion unmarshallAssertion(String assertionString) throws SamlParserException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Element element = db.parse(new ByteArrayInputStream(assertionString.getBytes(StandardCharsets.UTF_8)))
                    .getDocumentElement();
            return (Assertion) org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
                    .getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
        } catch (ParserConfigurationException | UnmarshallingException | org.xml.sax.SAXException |
                 java.io.IOException e) {
            logger.error("Failed to unmarshall SAML assertion", e);
            throw new SamlParserException("Failed to unmarshall SAML assertion", e);
        }
    }

    private void validateSignature(Assertion assertion, BasicX509Credential credential) throws SamlParserException {
        try {
            SignatureValidator.validate(assertion.getSignature(), credential);
        } catch (SignatureException e) {
            logger.error("Signature validation failed", e);
            throw new SamlParserException("Signature validation failed", e);
        }
    }

    private void validateConditions(Assertion assertion) throws SamlParserException {
        Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            throw new SamlParserException("Assertion conditions are missing");
        }

        Instant now = Instant.now();
        if (conditions.getNotBefore() != null && now.isBefore(conditions.getNotBefore())) {
            throw new SamlParserException("Assertion is not yet valid");
        }
        if (conditions.getNotOnOrAfter() != null && now.isAfter(conditions.getNotOnOrAfter())) {
            throw new SamlParserException("Assertion has expired");
        }
    }

    private void validateSubject(Assertion assertion) throws SamlParserException {
        Subject subject = assertion.getSubject();
        if (subject == null || subject.getNameID() == null) {
            throw new SamlParserException("Subject or NameID is missing");
        }
    }

    private IdentityInfo extractIdentityInfo(Assertion assertion) {
        IdentityInfo identityInfo = new IdentityInfo();

        // Extract NameID
        Subject subject = assertion.getSubject();
        if (subject != null && subject.getNameID() != null) {
            identityInfo.setUserId(subject.getNameID().getValue());
        }

        // Extract Issuer
        if (assertion.getIssuer() != null) {
            identityInfo.setIssuer(assertion.getIssuer().getValue());
        }

        // Extract Attributes
        for (AttributeStatement attrStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attrStatement.getAttributes()) {
                String name = attribute.getName();
                String value = attribute.getAttributeValues().get(0).getDOM().getTextContent();
                switch (name) {
                    case "trust_level":
                        identityInfo.setTrustLevel(value);
                        break;
                    case "session_id":
                        identityInfo.setSessionId(value);
                        break;
                    case "requested_application":
                        identityInfo.setRequestedApplication(value);
                        break;
                    case "subject_ip":
                        identityInfo.setSubjectIp(value);
                        break;
                    default:
                        identityInfo.addAttribute(name, value);
                }
            }
        }

        // Extract AuthnContext (as trust level if not already set)
        if (identityInfo.getTrustLevel() == null && assertion.getAuthnStatements() != null && !assertion.getAuthnStatements().isEmpty()) {
            AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
            if (authnStatement.getAuthnContext() != null && authnStatement.getAuthnContext().getAuthnContextClassRef() != null) {
                identityInfo.setTrustLevel(authnStatement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
            }
        }

        // Add a default authorization (this should be adjusted based on your authorization logic)
        identityInfo.addAuthorization(new Authorization(identityInfo.getRequestedApplication(), Authorization.DEFAULT_NAMESPACE, "read"));

        return identityInfo;
    }

    /**
     * Custom exception class for SAML parsing errors.
     */
    public static class SamlParserException extends Exception {
        public SamlParserException(String message) {
            super(message);
        }

        public SamlParserException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}