package dev.roshin.saml.config;

public class ProviderConfig {
    private final String keyAlias;
    private final String keystoreFile;
    private final String keystorePassword;
    private final String parseEncoding;

    public ProviderConfig(String keyAlias, String keystoreFile,
                          String keystorePassword, String parseEncoding) {
        this.keyAlias = keyAlias;
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
        this.parseEncoding = parseEncoding;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getKeystoreFile() {
        return keystoreFile;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getParseEncoding() {
        return parseEncoding;
    }

}
