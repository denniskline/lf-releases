package com.jpmc.gti.cassandra;
/*
File: EncryptedTextAuthProviderFactoryTest

Copyright 2019 JPMorgan Chase
All Rights Reserved
*/

import com.jpmc.gti.cassandra.reaper.auth.EncryptedTextAuthProviderFactory;
import org.junit.Test;

public class EncryptedTextAuthProviderFactoryTest {

    // ************************************************************************
    // Test Cases

    @Test(expected = IllegalArgumentException.class)
    public void fail_decoding_without_property_environment_setup() {
        EncryptedTextAuthProviderFactory factory = new EncryptedTextAuthProviderFactory();
        factory.setUsername("myusername");
        factory.setPassword("{cipher}aabbccddeefff11223344556677889900aabbccddeeff1122334455667788990");
        factory.setSystemPropertySecret("NO_SUCH_ENVIRONMENT");

        factory.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void fail_with_invalid_passphrase() {
        System.setProperty("MY_TEST_PROPERTY", "foo");
        EncryptedTextAuthProviderFactory factory = new EncryptedTextAuthProviderFactory();
        factory.setUsername("myusername");
        factory.setPassword("{cipher}aabbccddeefff11223344556677889900aabbccddeeff1122334455667788990");
        factory.setSystemPropertySecret("MY_TEST_PROPERTY");

        factory.build();
    }

}
