package com.jpmc.gti.cassandra.reaper.https;
/*
File: EncryptedHttpsConnectorFactory

Copyright 2019 JPMorgan Chase
All Rights Reserved
*/

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.jpmc.gti.cassandra.reaper.util.EncryptedTextBuilder;
import io.dropwizard.jetty.HttpsConnectorFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.validation.constraints.NotNull;

@JsonTypeName("encryptedHttps")
public class EncryptedHttpsConnectorFactory extends HttpsConnectorFactory {

    // ************************************************************************
    // Member Variables

    private String salt;
    private String cipher;
    @NotNull
    private String systemPropertySecret;

    // ************************************************************************
    // Implementation

    @Override
    protected SslContextFactory configureSslContextFactory(SslContextFactory factory) {
        setKeyStorePassword(decrypt(getKeyStorePassword()));
        setTrustStorePassword(decrypt(getTrustStorePassword()));
        return super.configureSslContextFactory(factory);
    }

    // ************************************************************************
    // Utility

    private String decrypt(String encyrptedText) {
        try {
            return EncryptedTextBuilder.create()
                    .withCipher(cipher)
                    .withSystemPropertySecret(systemPropertySecret)
                    .decrypt(encyrptedText);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid encyrpted password", e);
        }
    }

    // ************************************************************************
    // Accessors

    @JsonProperty
    public String getSalt() {
        return salt;
    }

    @JsonProperty
    public void setSalt(String salt) {
        this.salt = salt;
    }

    @JsonProperty
    public String getCipher() {
        return cipher;
    }

    @JsonProperty
    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    @JsonProperty
    public String getSystemPropertySecret() {
        return systemPropertySecret;
    }

    @JsonProperty
    public void setSystemPropertySecret(String systemPropertySecret) {
        this.systemPropertySecret = systemPropertySecret;
    }

}
