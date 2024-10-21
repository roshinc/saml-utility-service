package dev.roshin.saml.processing.domain;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents an authorization with a namespace, action, and resource.
 * This class is used to define and manage authorization rules.
 */
public class Authorization implements Serializable {
    /**
     * The default namespace for authorizations.
     */
    public static final String DEFAULT_NAMESPACE = "http://test.dev";
    /**
     * The default action for authorizations.
     */
    public static final String DEFAULT_ACTION = "any";
    private static final long serialVersionUID = 1L;
    private String namespace;
    private String action;
    private String resource;

    /**
     * Default constructor. Initializes with null resource, default namespace, and default action.
     */
    public Authorization() {
        this(null, DEFAULT_NAMESPACE, DEFAULT_ACTION);
    }

    /**
     * Constructor with resource. Initializes with given resource, default namespace, and default action.
     *
     * @param resource The resource to authorize
     */
    public Authorization(String resource) {
        this(resource, DEFAULT_NAMESPACE, DEFAULT_ACTION);
    }

    /**
     * Constructor with resource and action. Initializes with given resource and action, and default namespace.
     *
     * @param resource The resource to authorize
     * @param action   The action to authorize
     */
    public Authorization(String resource, String action) {
        this(resource, DEFAULT_NAMESPACE, action);
    }

    /**
     * Full constructor. Initializes all fields with given values.
     *
     * @param resource  The resource to authorize
     * @param namespace The namespace of the authorization
     * @param action    The action to authorize
     */
    public Authorization(String resource, String namespace, String action) {
        this.resource = resource;
        this.namespace = namespace;
        this.action = action;
    }

    /**
     * Gets the namespace of the authorization.
     *
     * @return The namespace
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * Sets the namespace of the authorization.
     *
     * @param namespace The namespace to set
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * Gets the action of the authorization.
     *
     * @return The action
     */
    public String getAction() {
        return action;
    }

    /**
     * Sets the action of the authorization.
     *
     * @param action The action to set
     */
    public void setAction(String action) {
        this.action = action;
    }

    /**
     * Gets the resource of the authorization.
     *
     * @return The resource
     */
    public String getResource() {
        return resource;
    }

    /**
     * Sets the resource of the authorization.
     *
     * @param resource The resource to set
     */
    public void setResource(String resource) {
        this.resource = resource;
    }

    /**
     * Returns a string representation of the Authorization object.
     *
     * @return A string representation of this Authorization
     */
    @Override
    public String toString() {
        return "Authorization{" +
                "resource='" + resource + '\'' +
                ", namespace='" + namespace + '\'' +
                ", action='" + action + '\'' +
                '}';
    }

    /**
     * Indicates whether some other object is "equal to" this one.
     *
     * @param o The reference object with which to compare
     * @return true if this object is the same as the o argument; false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Authorization that = (Authorization) o;
        return Objects.equals(namespace, that.namespace) &&
                Objects.equals(action, that.action) &&
                Objects.equals(resource, that.resource);
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return A hash code value for this object
     */
    @Override
    public int hashCode() {
        return Objects.hash(namespace, action, resource);
    }
}