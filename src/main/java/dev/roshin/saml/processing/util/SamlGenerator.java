package dev.roshin.saml.processing.util;

import dev.roshin.saml.processing.domain.IdentityInfo;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * A class for generating SAML 2.0 assertions using OpenSAML 4.x.
 */
public class SamlGenerator {

    private static final Logger logger = LoggerFactory.getLogger(SamlGenerator.class);

    /**
     * Constructor that initializes OpenSAML library.
     *
     * @throws InitializationException if OpenSAML initialization fails
     */
    public SamlGenerator() throws InitializationException {
        InitializationService.initialize();
        logger.info("SamlGenerator initialized with OpenSAML");
    }

    /**
     * Generates a signed SAML 2.0 assertion.
     *
     * @param identityInfo      The identity information to include in the assertion
     * @param signingCredential The credential to use for signing the assertion
     * @return A signed Assertion object
     * @throws Exception if assertion generation or signing fails
     */
    public Assertion generateAssertion(IdentityInfo identityInfo, Credential signingCredential) throws Exception {
        logger.debug("Generating SAML assertion for user: {}", identityInfo.getUserId());

        Assertion assertion = createSamlObject(Assertion.DEFAULT_ELEMENT_NAME);

        assertion.setID(generateId());
        assertion.setIssueInstant(Instant.now());
        assertion.setIssuer(buildIssuer(identityInfo.getIssuer()));
        assertion.setSubject(buildSubject(identityInfo.getUserId()));
        assertion.setConditions(buildConditions());
        assertion.getAttributeStatements().add(buildAttributeStatement(identityInfo));

        signAssertion(assertion, signingCredential);

        logger.info("SAML assertion generated successfully for user: {}", identityInfo.getUserId());
        return assertion;
    }

    /**
     * Marshals an Assertion object to its XML string representation.
     *
     * @param assertion The Assertion object to marshal
     * @return The XML string representation of the assertion
     * @throws MarshallingException if marshalling fails
     * @throws TransformerException if XML transformation fails
     */
    public String marshalAssertion(Assertion assertion) throws MarshallingException, TransformerException {
        Element element = XMLObjectSupport.marshall(assertion);
        return elementToString(element);
    }

    private <T> T createSamlObject(QName qName) {
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName).buildObject(qName);
    }

    private String generateId() {
        return "_" + java.util.UUID.randomUUID().toString();
    }

    private Issuer buildIssuer(String issuerValue) {
        Issuer issuer = createSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(issuerValue);
        return issuer;
    }

    private Subject buildSubject(String nameId) {
        Subject subject = createSamlObject(Subject.DEFAULT_ELEMENT_NAME);
        NameID nameID = createSamlObject(NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue(nameId);
        nameID.setFormat(NameIDType.UNSPECIFIED);
        subject.setNameID(nameID);
        return subject;
    }

    private Conditions buildConditions() {
        Conditions conditions = createSamlObject(Conditions.DEFAULT_ELEMENT_NAME);
        Instant now = Instant.now();
        conditions.setNotBefore(now);
        conditions.setNotOnOrAfter(now.plus(5, ChronoUnit.MINUTES));
        return conditions;
    }

    private AttributeStatement buildAttributeStatement(IdentityInfo identityInfo) {
        AttributeStatement attributeStatement = createSamlObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
        identityInfo.getAttributes().forEach((key, value) -> {
            Attribute attribute = createSamlObject(Attribute.DEFAULT_ELEMENT_NAME);
            attribute.setName(key);
            XSString attributeValue = createSamlObject(XSString.TYPE_NAME);
            attributeValue.setValue(value);
            attribute.getAttributeValues().add(attributeValue);
            attributeStatement.getAttributes().add(attribute);
        });
        return attributeStatement;
    }

    private void signAssertion(Assertion assertion, Credential signingCredential) throws SignatureException, MarshallingException, SecurityException {
        SignatureSigningParameters parameters = new SignatureSigningParameters();
        parameters.setSigningCredential(signingCredential);
        parameters.setSignatureAlgorithm(DefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration().getSignatureAlgorithms().get(0));
        parameters.setSignatureCanonicalizationAlgorithm(DefaultSecurityConfigurationBootstrap.buildDefaultSignatureSigningConfiguration().getSignatureCanonicalizationAlgorithm());

        SignatureSupport.signObject(assertion, parameters);
    }

    private String elementToString(Element element) throws TransformerException {
        Transformer tf = TransformerFactory.newInstance().newTransformer();
        tf.setOutputProperty(OutputKeys.INDENT, "yes");
        StringWriter writer = new StringWriter();
        tf.transform(new DOMSource(element), new StreamResult(writer));
        return writer.toString();
    }
}