package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.util.BinaryUtil;
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
    @JsonIgnore
    private byte[] id;

    private Optional<List<AuthenticatorTransport>> transports = Optional.empty();

    public PublicKeyCredentialDescriptor(@NonNull PublicKeyCredentialType type, @NonNull byte[] id) {
        this.type = type;
        this.id = id;
    }

    public PublicKeyCredentialDescriptor(@NonNull byte[] id) {
        this(PublicKeyCredentialType.PUBLIC_KEY, id);
    }

    public byte[] getId() {
        return BinaryUtil.copy(id);
    }

    @JsonProperty("id")
    public String getIdBase64() {
        return U2fB64Encoding.encode(id);
    }

}
