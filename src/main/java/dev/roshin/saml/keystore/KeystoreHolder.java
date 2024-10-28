package dev.roshin.saml.keystore;

import dev.roshin.saml.domain.CertificateInfo;
import dev.roshin.saml.domain.KeystoreMetadataException;
import org.opensaml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Class representing a Java KeyStore (JKS) that manages X.509 credentials.
 */
public class KeystoreHolder {
    private static final Logger logger = LoggerFactory.getLogger(KeystoreHolder.class.getName());

    private final KeyStore keystore;
    private final Path keystorePath;
    private final String keystorePassword;
    private final String keyAlias;
    private final BasicX509Credential currentCredential;

    /**
     * Constructor to initialize the KeystoreHolder.
     *
     * @param keystorePath     Path to the keystore file
     * @param keystorePassword Password for the keystore
     * @param keyAlias         Alias of the key entry
     * @throws Exception If initialization fails
     */
    public KeystoreHolder(Path keystorePath, String keystorePassword, String keyAlias) throws Exception {
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
        this.keystore = initializeKeystore();
        this.currentCredential = loadCredential();
    }

    /**
     * Initializes the keystore from the file.
     *
     * @return Initialized KeyStore object
     * @throws Exception If initialization fails
     */
    private KeyStore initializeKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream keystoreStream = Files.newInputStream(keystorePath)) {
            ks.load(keystoreStream, keystorePassword.toCharArray());
            logger.info("Keystore loaded successfully from path: {}", keystorePath);
            return ks;
        } catch (Exception e) {
            logger.error("Failed to load keystore from path: {}", keystorePath, e);
            throw e;
        }
    }

    /**
     * Loads the X.509 credential from the keystore.
     *
     * @return BasicX509Credential containing the private key and certificate
     * @throws Exception If loading fails
     */
    private BasicX509Credential loadCredential() throws Exception {
        try {
            PasswordProtection keyPassword = new PasswordProtection(keystorePassword.toCharArray());
            KeyStore.Entry entry = keystore.getEntry(keyAlias, keyPassword);

            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new KeyStoreException("No private key found for alias: " + keyAlias);
            }

            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            Certificate cert = keystore.getCertificate(keyAlias);

            if (!(cert instanceof X509Certificate)) {
                throw new KeyStoreException("Certificate for alias " + keyAlias + " is not an X509Certificate");
            }

            X509Certificate x509Cert = (X509Certificate) cert;
            return new BasicX509Credential(x509Cert, privateKey);

        } catch (Exception e) {
            logger.error("Failed to retrieve credentials for alias: {}", keyAlias, e);
            throw e;
        }
    }

    /**
     * Gets the current X.509 credential.
     *
     * @return The current BasicX509Credential
     */
    public BasicX509Credential getCredential() {
        return currentCredential;
    }

    /**
     * Gets the keystore path.
     *
     * @return The keystore file path
     */
    public Path getKeystorePath() {
        return keystorePath;
    }

    /**
     * Gets the keystore name (filename from path).
     *
     * @return The keystore filename
     */
    public String getKeystoreName() {
        return keystorePath.getFileName().toString();
    }

    /**
     * Gets the key alias.
     *
     * @return The key alias
     */
    public String getKeyAlias() {
        return keyAlias;
    }

    /**
     * Gets the certificate for the current alias.
     *
     * @return The X509Certificate
     * @throws KeyStoreException If certificate retrieval fails
     */
    public X509Certificate getCertificate() throws KeyStoreException {
        Certificate cert = keystore.getCertificate(keyAlias);
        if (cert instanceof X509Certificate) {
            return (X509Certificate) cert;
        }
        throw new KeyStoreException("Certificate for alias " + keyAlias + " is not an X509Certificate");
    }

    /**
     * Creates a CertificateInfo object containing metadata about all certificates in the keystore.
     *
     * @return CertificateInfo containing certificate metadata
     * @throws Exception If metadata retrieval fails
     */
    public CertificateInfo getMetadata() throws Exception {
        logger.debug("Retrieving metadata for keystore: {}", keystorePath);

        List<CertificateInfo.CertificateDetails> certificateDetails = new ArrayList<>();

        try {
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keystore.getCertificate(alias);

                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    certificateDetails.add(extractCertificateDetails(x509Cert, alias));
                    logger.trace("Added certificate details for alias: {}", alias);
                }
            }

            CertificateInfo info = new CertificateInfo(
                    keystorePath.toString(),
                    getKeystoreName(),
                    keyAlias,
                    keystore.getType(),
                    keystore.size(),
                    certificateDetails
            );

            logger.debug("Successfully retrieved metadata for keystore: {}", keystorePath);
            return info;

        } catch (Exception e) {
            logger.error("Failed to retrieve keystore metadata for path: {}", keystorePath, e);
            throw new KeystoreMetadataException("Failed to retrieve keystore metadata", e);
        }
    }

    /**
     * Extracts details from an X509Certificate into a CertificateDetails record.
     *
     * @param cert  The X509Certificate to extract details from
     * @param alias The alias of the certificate
     * @return CertificateDetails containing the extracted information
     */
    private CertificateInfo.CertificateDetails extractCertificateDetails(X509Certificate cert, String alias) {
        return new CertificateInfo.CertificateDetails(
                alias,
                cert.getSubjectX500Principal().getName(),
                cert.getIssuerX500Principal().getName(),
                cert.getSerialNumber().toString(),
                cert.getNotBefore().toString(),
                cert.getNotAfter().toString(),
                alias.equals(keyAlias)
        );
    }

    @Override
    public String toString() {
        return String.format("KeystoreHolder{path='%s', name='%s', alias='%s', password='%s'}",
                keystorePath,
                getKeystoreName(),
                keyAlias,
                "********");
    }
}