package com.jpmc.gti.cassandra.reaper.auth;
/*
File: KerberosAuthProviderFactory

Copyright 2019 JPMorgan Chase
All Rights Reserved
*/

import com.datastax.driver.core.AuthProvider;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.jpmc.gti.cassandra.driver.auth.KerberosAuthProvider;
import systems.composable.dropwizard.cassandra.auth.AuthProviderFactory;

/**
 * Reaper must be started with krb5 toggles:
 * <UL>
 * <LI>-Djava.security.auth.login.config=kerb-client.conf </LI>
 * </UL>
 */
@JsonTypeName("kerberos")
public class KerberosAuthProviderFactory implements AuthProviderFactory {

    // ************************************************************************
    // Implementation

    @Override
    public AuthProvider build() {
        return KerberosAuthProvider.builder().withSaslProtocol("caas").build();
    }

}
