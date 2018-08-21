package com.yubico.webauthn.data;

public interface Credential {

    ByteArray getId();
    String getType();

}
