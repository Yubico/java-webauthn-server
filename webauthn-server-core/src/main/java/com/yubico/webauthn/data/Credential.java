package com.yubico.webauthn.data;

public interface Credential {

    ByteArray getId();

    PublicKeyCredentialType getType();

}
