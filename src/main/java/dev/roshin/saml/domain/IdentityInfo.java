package dev.roshin.saml.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents identity information, including attributes and authorizations.
 * This class is used to store and manage user identity data.
 */
public class IdentityInfo implements Serializable {
    /**
     * The default issuer for identity information.
     */
    public static final String DEFAULT_ISSUER = "http://test.dev";
    private static final long serialVersionUID = 1L;
    private final Map<String, String> attributes;
    private final Map<String, List<Authorization>> authorizations;

    /**
     * Default constructor. Initializes empty maps for attributes and authorizations.
     */
    public IdentityInfo() {
        this.attributes = new HashMap<>();
        this.authorizations = new HashMap<>();
    }

    /**
     * Gets the user ID.
     *
     * @return The user ID
     */
    public String getUserId() {
        return getAttribute(IAttributeKeys.USER_ID);
    }

    /**
     * Sets the user ID.
     *
     * @param userId The user ID to set
     */
    public void setUserId(String userId) {
        addAttribute(IAttributeKeys.USER_ID, userId);
    }

    /**
     * Gets the issuer.
     *
     * @return The issuer
     */
    public String getIssuer() {
        return getAttribute(IAttributeKeys.ISSUER);
    }

    /**
     * Sets the issuer.
     *
     * @param issuer The issuer to set
     */
    public void setIssuer(String issuer) {
        addAttribute(IAttributeKeys.ISSUER, issuer);
    }

    /**
     * Gets the subject IP.
     *
     * @return The subject IP
     */
    public String getSubjectIp() {
        return getAttribute(IAttributeKeys.SUBJECT_IP);
    }

    /**
     * Sets the subject IP.
     *
     * @param subjectIp The subject IP to set
     */
    public void setSubjectIp(String subjectIp) {
        addAttribute(IAttributeKeys.SUBJECT_IP, subjectIp);
    }

    /**
     * Gets the trust level.
     *
     * @return The trust level
     */
    public String getTrustLevel() {
        return getAttribute(IAttributeKeys.TRUST_LEVEL);
    }

    /**
     * Sets the trust level.
     *
     * @param trustLevel The trust level to set
     */
    public void setTrustLevel(String trustLevel) {
        addAttribute(IAttributeKeys.TRUST_LEVEL, trustLevel);
    }

    /**
     * Gets the session ID.
     *
     * @return The session ID
     */
    public String getSessionId() {
        return getAttribute(IAttributeKeys.SESSION_ID);
    }

    /**
     * Sets the session ID.
     *
     * @param sessionId The session ID to set
     */
    public void setSessionId(String sessionId) {
        addAttribute(IAttributeKeys.SESSION_ID, sessionId);
    }

    /**
     * Gets the session token.
     *
     * @return The session token
     */
    public String getSessionToken() {
        return getAttribute(IAttributeKeys.SESSION_TOKEN);
    }

    /**
     * Sets the session token.
     *
     * @param sessionToken The session token to set
     */
    public void setSessionToken(String sessionToken) {
        addAttribute(IAttributeKeys.SESSION_TOKEN, sessionToken);
    }

    /**
     * Gets the requested application.
     *
     * @return The requested application
     */
    public String getRequestedApplication() {
        return getAttribute(IAttributeKeys.REQUESTED_APPLICATION);
    }

    /**
     * Sets the requested application.
     *
     * @param requestedApplication The requested application to set
     */
    public void setRequestedApplication(String requestedApplication) {
        addAttribute(IAttributeKeys.REQUESTED_APPLICATION, requestedApplication);
    }

    /**
     * Gets an attribute by name.
     *
     * @param name The name of the attribute
     * @return The value of the attribute
     */
    public String getAttribute(String name) {
        return attributes.get(name);
    }

    /**
     * Adds an attribute.
     *
     * @param name  The name of the attribute
     * @param value The value of the attribute
     */
    public void addAttribute(String name, String value) {
        attributes.put(name, value);
    }

    /**
     * Adds an authorization.
     *
     * @param authorization The authorization to add
     */
    public void addAuthorization(Authorization authorization) {
        authorizations.computeIfAbsent(authorization.getResource(), k -> new ArrayList<>()).add(authorization);
    }

    /**
     * Gets all attributes.
     *
     * @return A copy of the attributes map
     */
    public Map<String, String> getAttributes() {
        return new HashMap<>(attributes);
    }

    /**
     * Gets all authorizations.
     *
     * @return A copy of the authorizations map
     */
    public Map<String, List<Authorization>> getAuthorizations() {
        return new HashMap<>(authorizations);
    }

    /**
     * Returns a string representation of the IdentityInfo object.
     *
     * @return A string representation of this IdentityInfo
     */
    @Override
    public String toString() {
        return "IdentityInfo{" +
                "attributes=" + attributes +
                ", authorizations=" + authorizations +
                '}';
    }
}