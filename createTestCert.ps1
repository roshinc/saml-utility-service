#keytool -genkeypair -alias samlkey -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -keystore samlkeystore.jks -storepass your_keystore_password
keytool -genkeypair -alias mykeyalias -keyalg RSA -keysize 2048 -keystore test-keystore.jks -storepass changeit -validity 3650 -dname "CN=Test, OU=Test, O=Test, L=Test, S=Test, C=US"
