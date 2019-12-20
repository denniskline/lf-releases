package com.jpmc.gti.cassandra.reaper.auth;
/*
File: EncryptedTextAuthProviderFactory

Copyright 2019 JPMorgan Chase
All Rights Reserved
*/

import com.datastax.driver.core.AuthProvider;
import com.datastax.driver.core.PlainTextAuthProvider;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.jpmc.gti.cassandra.reaper.util.EncryptedTextBuilder;
import systems.composable.dropwizard.cassandra.auth.AuthProviderFactory;

import javax.validation.constraints.NotNull;

@JsonTypeName("encryptedText")
public class EncryptedTextAuthProviderFactory implements AuthProviderFactory {

    // ************************************************************************
    // Member Variables

    @NotNull
    private String username;
    @NotNull
    private String password;
    private String salt;
    private String cipher;
    @NotNull
    private String systemPropertySecret;

    // ************************************************************************
    // Implementation

    @Override
    public AuthProvider build() {
        try {
            String decrypted = EncryptedTextBuilder.create()
                    .withCipher(cipher)
                    .withSystemPropertySecret(systemPropertySecret)
                    .decrypt(password);
            return new PlainTextAuthProvider(username, decrypted);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid encyrpted password", e);
        }
    }

    // ************************************************************************
    // Accessors

    @JsonProperty
    public String getUsername() {
        return username;
    }

    @JsonProperty
    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty
    public String getPassword() {
        return password;
    }

    @JsonProperty
    public void setPassword(String password) {
        this.password = password;
    }

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
