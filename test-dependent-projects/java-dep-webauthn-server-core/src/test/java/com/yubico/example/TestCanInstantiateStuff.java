package com.yubico.example;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class TestCanInstantiateStuff {

    @Test
    public void byteArray() {
        ByteArray a = new ByteArray(new byte[] {1, 2, 3, 4});
        assertNotNull(a);
        assertNotNull(a.getBytes());
    }

    @Test
    public void publicKeyCredentialType() {
        PublicKeyCredentialType a = PublicKeyCredentialType.PUBLIC_KEY;
        assertNotNull(a);
        assertNotNull(a.toJsonString());
    }

}
