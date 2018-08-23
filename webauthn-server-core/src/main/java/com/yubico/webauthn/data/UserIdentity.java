package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.util.BinaryUtil;
import java.net.URL;
import java.util.Optional;
import lombok.Builder;
import lombok.Getter;
import lombok.Value;


/**
 * Describes a user account, with which a public key credential is to be associated.
 */
@Value
@Builder
public class UserIdentity implements PublicKeyCredentialEntity {

    /**
     * A name for the user account.
     * <p>
     * For example: "john.p.smith@example.com" or "+14255551234".
     */
    private String name;

    /**
     * A friendly name for the user account (e.g. "Ryan A. Smith").
     */
    private String displayName;

    /**
     * An identifier for the account, specified by the Relying Party.
     * <p>
     * This is not meant to be displayed to the user, but is used by the Relying Party to control the number of
     * credentials - an authenticator will never contain more than one credential for a given Relying Party under the
     * same id.
     */
    @JsonIgnore
    private byte[] id;

    /**
     * A URL which resolves to an image associated with the user account.
     * <p>
     * For example, this could be the user's avatar.
     */
    @Builder.Default
    private Optional<URL> icon = Optional.empty();

    public byte[] getId() {
        return BinaryUtil.copy(id);
    }

    @JsonProperty("id")
    public String getIdBase64() {
        return U2fB64Encoding.encode(id);
    }

}
