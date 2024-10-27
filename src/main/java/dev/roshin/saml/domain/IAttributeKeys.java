package dev.roshin.saml.domain;

/**
 * Interface defining constant keys for various attributes used in the identity management system.
 */
public interface IAttributeKeys {
    /**
     * Key for the user ID attribute.
     */
    String USER_ID = "SESSION_USERID";

    /**
     * Key for the issuer attribute.
     */
    String ISSUER = "ISSUER";

    /**
     * Key for the requested application attribute.
     */
    String REQUESTED_APPLICATION = "REQUESTED_APPLICATION";

    /**
     * Key for the trust level attribute.
     */
    String TRUST_LEVEL = "TRUST_LEVEL";

    /**
     * Key for the session ID attribute.
     */
    String SESSION_ID = "SESSION_ID";

    /**
     * Key for the session token attribute.
     */
    String SESSION_TOKEN = "SESSION_TOKEN";

    /**
     * Key for the IP address attribute.
     */
    String IP_ADDRESS = "IP_ADDRESS";

    /**
     * Key for the subject IP attribute.
     */
    String SUBJECT_IP = "SUBJECT_IP";
}