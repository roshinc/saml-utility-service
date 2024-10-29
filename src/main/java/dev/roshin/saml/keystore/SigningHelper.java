package dev.roshin.saml.keystore;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class for signing SAML responses and assertions using credentials from a KeystoreHolder.
 * Note: This class uses the RSA-SHA1 signature algorithm for legacy compatibility, which is considered insecure.
 * It is strongly recommended to upgrade to RSA-SHA256 or a more secure algorithm.
 */
public class SigningHelper {
    private static final Logger logger = LoggerFactory.getLogger(SigningHelper.class);

    private final KeystoreHolder keystoreHolder;

    /**
     * Constructs a SigningHelper with the provided KeystoreHolder.
     *
     * @param keystoreHolder The KeystoreHolder containing the signing credentials
     */
    public SigningHelper(KeystoreHolder keystoreHolder) {
        this.keystoreHolder = keystoreHolder;
        logger.info("SigningHelper initialized with keystore: {}", keystoreHolder.getKeystoreName());
    }

    /**
     * Signs a SAML Response using RSA signature with exclusive canonicalization.
     * <p>
     * Note: RSA-SHA1 is deprecated and insecure. It is recommended to use RSA-SHA256 instead.
     *
     * @param response The SAML Response to sign
     * @throws Exception if there are issues during the signing process
     */
    public void signResponse(Response response) throws Exception {
        String methodName = "signResponse";
        logger.debug("{} Signing response with ID: {}", methodName, response.getID());

        try {
            signSAMLObject(response, methodName);
        } catch (Exception e) {
            logger.error("{} Failed to sign response", methodName, e);
            throw e;
        }
    }

    /**
     * Signs a SAML Assertion using RSA signature with exclusive canonicalization.
     * <p>
     * Note: RSA-SHA1 is deprecated and insecure. It is recommended to use RSA-SHA256 instead.
     *
     * @param assertion The SAML Assertion to sign
     * @throws Exception if there are issues during the signing process
     */
    public void signAssertion(Assertion assertion) throws Exception {
        String methodName = "signAssertion";
        logger.debug("{} Signing assertion with ID: {}", methodName, assertion.getID());

        try {
            signSAMLObject(assertion, methodName);
        } catch (Exception e) {
            logger.error("{} Failed to sign assertion", methodName, e);
            throw e;
        }
    }

    /**
     * Internal method to sign any SAML SignableXMLObject (Response or Assertion).
     *
     * @param object     The SAML object to sign
     * @param methodName The calling method name for logging
     * @throws Exception if there are issues during the signing process
     */
    private void signSAMLObject(SignableXMLObject object, String methodName) throws Exception {
        if (object == null) {
            throw new IllegalArgumentException("Cannot sign null object");
        }

        try {
            // Create signature object
            Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
                    .getBuilderOrThrow(Signature.DEFAULT_ELEMENT_NAME)
                    .buildObject(Signature.DEFAULT_ELEMENT_NAME);

            // Set signature properties
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            // Note: The use of RSA-SHA1 (ALGO_ID_SIGNATURE_RSA) is deprecated and insecure.
            // It is recommended to use RSA-SHA256 (ALGO_ID_SIGNATURE_RSA_SHA256) for better security.

            // Get and set the credential
            BasicX509Credential credential = keystoreHolder.getCredential();
            signature.setSigningCredential(credential);

            // Set the signature in the SAML object
            object.setSignature(signature);

            // Prepare signature parameters
            SignatureSigningParameters parameters = new SignatureSigningParameters();
            parameters.setSigningCredential(credential);
            parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
            parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1);
            // Note: SHA-1 digest method is insecure. Use ALGO_ID_DIGEST_SHA256 if possible.

            // Set KeyInfoGenerator
            KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            parameters.setKeyInfoGenerator(keyInfoGeneratorFactory.newInstance());

            // Marshal the object
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
            if (marshaller == null) {
                throw new MarshallingException("No marshaller registered for " + object.getElementQName());
            }
            marshaller.marshall(object);

            // Sign the object
            SignatureSupport.signObject(object, parameters);

            logger.debug("{} Successfully signed SAML object", methodName);

        } catch (MarshallingException | SignatureException e) {
            logger.error("{} Error during signing", methodName, e);
            throw e;
        } catch (Exception e) {
            logger.error("{} Unexpected error during signing", methodName, e);
            throw new Exception("Unexpected error during signing", e);
        }
    }

    /**
     * Verifies if an object has been properly signed.
     *
     * @param object The SAML object to verify
     * @return true if the object is signed, false otherwise
     */
    public boolean isSigned(SignableXMLObject object) {
        return object != null && object.getSignature() != null;
    }
}
