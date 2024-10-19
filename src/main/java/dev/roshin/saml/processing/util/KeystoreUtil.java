package dev.roshin.saml.processing.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.opensaml.security.x509.BasicX509Credential;

/**
 * Utility class to load X.509 credentials from a Java KeyStore (JKS) file.
 */
public class KeystoreUtil {
    private static final Logger logger = Logger.getLogger(KeystoreUtil.class.getName());

    /**
     * Loads an X.509 credential from a JKS keystore.
     * 
     * @param keystorePath     Path to the keystore file.
     * @param keystorePassword Password for the keystore.
     * @param keyAlias         Alias of the key entry.
     * @return A BasicX509Credential containing the private key and certificate.
     * @throws Exception If an error occurs while loading the credential.
     */
    public static BasicX509Credential init(String keystorePath, String keystorePassword, String keyAlias)
            throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");

        // Load the keystore
        try (InputStream keystoreStream = new FileInputStream(keystorePath)) {
            keystore.load(keystoreStream, keystorePassword.toCharArray());
            logger.info("Keystore loaded successfully from path: " + keystorePath);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to load keystore from path: " + keystorePath, e);
            throw e;
        }

        // Retrieve the private key and certificate
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

            BasicX509Credential credential = new BasicX509Credential(x509Cert, privateKey);
            logger.info("Credential loaded successfully for alias: " + keyAlias);
            return credential;

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to retrieve credentials for alias: " + keyAlias, e);
            throw e;
        }
    }
}
