package com.yubico.webauthn.data;

import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;


/**
 * The attributes that are specified by a caller when referring to a credential as an input parameter to the create() or
 * get() methods. It mirrors the fields of the [[PublicKeyCredential]] object returned by the latter methods.
 */
@Value
public class PublicKeyCredentialDescriptor {

    /**
     * The type of the credential the caller is referring to.
     */
    private PublicKeyCredentialType type;

    /**
     * The identifier of the credential that the caller is referring to.
     */
    private ByteArray id;

    private Optional<List<AuthenticatorTransport>> transports = Optional.empty();

    public PublicKeyCredentialDescriptor(@NonNull PublicKeyCredentialType type, @NonNull ByteArray id) {
        this.type = type;
        this.id = id;
    }

    public PublicKeyCredentialDescriptor(@NonNull ByteArray id) {
        this(PublicKeyCredentialType.PUBLIC_KEY, id);
    }

}
