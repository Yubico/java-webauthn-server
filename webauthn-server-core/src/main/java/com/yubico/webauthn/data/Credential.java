package com.yubico.webauthn.data;

import com.yubico.util.ByteArray;

public interface Credential {

    ByteArray getId();

    PublicKeyCredentialType getType();

}
