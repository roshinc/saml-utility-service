package dev.roshin.saml;

import dev.roshin.saml.domain.IdentityInfo;
import dev.roshin.saml.keystore.KeystoreHolder;
import dev.roshin.saml.keystore.SigningHelper;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Generates SAML assertions and responses using modern OpenSAML libraries.
 * This class is thread-safe and can be used in a multi-threaded environment.
 */
public class SamlAssertionGenerator {
    private static final Logger logger = LoggerFactory.getLogger(SamlAssertionGenerator.class);

    private static final int NOT_BEFORE_SECONDS = 300; // 5 minutes
    private static final int NOT_AFTER_SECONDS = 600;  // 10 minutes

    private final KeystoreHolder keystoreHolder;
    private final SigningHelper signingHelper;

    public SamlAssertionGenerator(KeystoreHolder keystoreHolder, SigningHelper signingHelper) {
        this.keystoreHolder = keystoreHolder;
        this.signingHelper = signingHelper;
    }

    /**
     * Creates a signed and optionally encrypted SAML assertion from identity information.
     *
     * @param info The identity information to use for assertion creation
     * @return Base64 encoded SAML assertion string
     * @throws Exception if there's an error during assertion creation
     */
    public String createAssertion(IdentityInfo info) throws Exception {
        logger.debug("Creating SAML assertion for user: {}", info.getUserId());

        try {
            Instant now = Instant.now();

            // Create the SAML Response
            Response response = createResponse(info, now);
            response.setStatus(createStatus("urn:oasis:names:tc:SAML:2.0:status:Success"));

            // Build and sign the assertion
            Assertion assertion = buildAssertion(info, now);
            signingHelper.signAssertion(assertion);

            // Handle encryption if needed
            String audience = getAudience(info);
            String alias = getConfiguredAlias(audience);

            if (alias != null && !alias.isEmpty()) {
                logger.debug("Encrypting assertion with alias: {}", alias);
                EncryptedAssertion encryptedAssertion = encryptAssertion(alias, assertion);
                response.getEncryptedAssertions().add(encryptedAssertion);
            } else {
                logger.debug("Adding unencrypted assertion to response");
                response.getAssertions().add(assertion);
            }

            // Sign the response
            signingHelper.signResponse(response);

            // Convert to string and encode
            String samlString = elementToString(response);
            return Base64.getEncoder().encodeToString(samlString.getBytes());

        } catch (Exception e) {
            logger.error("Error creating SAML assertion", e);
            throw new SamlGenerationException("Failed to create SAML assertion", e);
        }
    }

    private Response createResponse(IdentityInfo info, Instant issueInstant) {
        Response response = new ResponseBuilder().buildObject();
        response.setID("_" + UUID.randomUUID().toString());
        response.setIssueInstant(issueInstant);
        response.setVersion(SAMLVersion.VERSION_20);

        String destination = info.getAttribute("destination");
        if (destination != null && !destination.isEmpty()) {
            response.setDestination(destination);
        }

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(info.getIssuer() != null ? info.getIssuer() : IdentityInfo.DEFAULT_ISSUER);
        response.setIssuer(issuer);

        return response;
    }

    private Status createStatus(String statusCode) {
        Status status = new StatusBuilder().buildObject();
        StatusCode code = new StatusCodeBuilder().buildObject();
        code.setValue(statusCode);
        status.setStatusCode(code);
        return status;
    }

    private Assertion buildAssertion(IdentityInfo info, Instant issueInstant) {
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID("_" + UUID.randomUUID().toString());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_20);

        // Set issuer
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(info.getIssuer() != null ? info.getIssuer() : IdentityInfo.DEFAULT_ISSUER);
        assertion.setIssuer(issuer);

        // Create subject
        Subject subject = createSubject(info, issueInstant);
        assertion.setSubject(subject);

        // Create conditions
        Conditions conditions = createConditions(info, issueInstant);
        assertion.setConditions(conditions);

        // Create authentication statement
        AuthnStatement authnStatement = createAuthnStatement(info, issueInstant);
        assertion.getAuthnStatements().add(authnStatement);

        // Create attribute statement if there are attributes
        AttributeStatement attrStatement = createAttributeStatement(info);
        if (attrStatement != null) {
            assertion.getAttributeStatements().add(attrStatement);
        }

        // Create authorization decision statements
        createAuthzDecisionStatements(info, assertion);

        return assertion;
    }

    private Subject createSubject(IdentityInfo info, Instant issueInstant) {
        Subject subject = new SubjectBuilder().buildObject();

        // Create NameID
        String userId = info.getUserId();
        if (userId == null || userId.isEmpty()) {
            throw new SamlGenerationException("User ID is required for SAML assertion");
        }
        logger.debug("Building subject for user: {}", info.getUserId());
        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setValue(userId);
        nameId.setFormat(NameID.PERSISTENT);
        subject.setNameID(nameId);

        // Create SubjectConfirmation
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData confirmationData = new SubjectConfirmationDataBuilder().buildObject();
        confirmationData.setNotOnOrAfter(issueInstant.plus(10, ChronoUnit.MINUTES));

        String destination = info.getAttribute("destination");
        if (destination != null && !destination.isEmpty()) {
            confirmationData.setRecipient(destination);
        }

        subjectConfirmation.setSubjectConfirmationData(confirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    private Conditions createConditions(IdentityInfo info, Instant issueInstant) {
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(issueInstant.minus(NOT_BEFORE_SECONDS, ChronoUnit.SECONDS));
        conditions.setNotOnOrAfter(issueInstant.plus(NOT_AFTER_SECONDS, ChronoUnit.SECONDS));

        // Create AudienceRestriction
        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience audience = new AudienceBuilder().buildObject();
        //audience.setAudienceURI(getAudience(info));
        audience.setURI(getAudience(info));
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        return conditions;
    }

    private AuthnStatement createAuthnStatement(IdentityInfo info, Instant issueInstant) {
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(issueInstant);
        authnStatement.setSessionIndex(info.getSessionId());

        AuthnContext authnContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef classRef = new AuthnContextClassRefBuilder().buildObject();
        //classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        classRef.setURI("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        authnContext.setAuthnContextClassRef(classRef);
        authnStatement.setAuthnContext(authnContext);

        String ipAddress = info.getSubjectIp();
        if (ipAddress != null && !ipAddress.isEmpty()) {
            SubjectLocality subjectLocality = new SubjectLocalityBuilder().buildObject();
            subjectLocality.setAddress(ipAddress);
            authnStatement.setSubjectLocality(subjectLocality);
        }

        return authnStatement;
    }

    private AttributeStatement createAttributeStatement(IdentityInfo info) {
        Map<String, String> attributes = info.getAttributes();
        if (attributes == null || attributes.isEmpty()) {
            return null;
        }

        AttributeStatement statement = new AttributeStatementBuilder().buildObject();

        attributes.forEach((key, value) -> {
            try {
                Attribute attribute = new AttributeBuilder().buildObject();
                attribute.setName(key);

                XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport
                        .getBuilderFactory().getBuilder(XSString.TYPE_NAME);
                if (stringBuilder == null) {
                    logger.warn("No XSStringBuilder available for attribute: {}", key);
                    return;
                }
                XSString stringValue = stringBuilder.buildObject(
                        AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                stringValue.setValue(value);

                attribute.getAttributeValues().add(stringValue);
                statement.getAttributes().add(attribute);
            } catch (Exception e) {
                logger.warn("Failed to add attribute: {} = {}", key, value, e);
            }
        });

        return statement;
    }

    private void createAuthzDecisionStatements(IdentityInfo info, Assertion assertion) {
        if (info.getRequestedApplication() == null || info.getAuthorizations().isEmpty()) {
            return;
        }

        info.getAuthorizations().forEach((resourceId, authorizations) -> {
            AuthzDecisionStatement authzStatement = new AuthzDecisionStatementBuilder().buildObject();
            authzStatement.setResource(resourceId);
            authzStatement.setDecision(DecisionTypeEnumeration.PERMIT);

            authorizations.forEach(authorization -> {
                Action action = new ActionBuilder().buildObject();
                action.setNamespace(authorization.getNamespace());
                action.setValue(authorization.getAction());
                authzStatement.getActions().add(action);
            });

            assertion.getAuthzDecisionStatements().add(authzStatement);
        });
    }

    private EncryptedAssertion encryptAssertion(String alias, Assertion assertion) {
        logger.debug("Encrypting assertion with alias: {}", alias);

        Credential encryptionCredential = keystoreHolder.getCredential();

        // Set up encryption parameters
        DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);

        // Set up key encryption parameters
        KeyEncryptionParameters keyParams = new KeyEncryptionParameters();
        keyParams.setEncryptionCredential(encryptionCredential);
        keyParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        // Create and configure the encrypter
        Encrypter encrypter = new Encrypter(encParams, keyParams);

        try {
            return encrypter.encrypt(assertion);
        } catch (Exception e) {
            logger.error("Failed to encrypt assertion", e);
            throw new SamlGenerationException("Failed to encrypt assertion", e);
        }
    }

    private String elementToString(XMLObject xmlObject) throws Exception {
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(xmlObject);
        if (marshaller == null) {
            throw new SamlGenerationException("No marshaller registered for object: " + xmlObject.getElementQName());
        }
        Element element = marshaller.marshall(xmlObject);

        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer = transFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

        StringWriter buffer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(buffer));

        return buffer.toString();
    }

    private String getAudience(IdentityInfo info) {
        return info.getAttribute("audience") != null ?
                info.getAttribute("audience") :
                "defaultAudience";
    }

    private String getConfiguredAlias(String audience) {
        // This should be replaced with your actual configuration lookup
        return System.getProperty(audience + ".alias");
    }
}

