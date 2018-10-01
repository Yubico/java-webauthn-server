package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URL;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * Describes a user account, with which a public key credential is to be associated.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class UserIdentity implements PublicKeyCredentialEntity {

    /**
     * A name for the user account.
     * <p>
     * For example: "john.p.smith@example.com" or "+14255551234".
     */
    @NonNull
    private final String name;

    /**
     * A friendly name for the user account (e.g. "Ryan A. Smith").
     */
    @NonNull
    private final String displayName;

    /**
     * An identifier for the account, specified by the Relying Party.
     * <p>
     * This is not meant to be displayed to the user, but is used by the Relying Party to control the number of
     * credentials - an authenticator will never contain more than one credential for a given Relying Party under the
     * same id.
     */
    @NonNull
    private final ByteArray id;

    /**
     * A URL which resolves to an image associated with the user account.
     * <p>
     * For example, this could be the user's avatar.
     */
    @NonNull
    @Builder.Default
    private final Optional<URL> icon = Optional.empty();

    @JsonCreator
    private UserIdentity(
        @NonNull @JsonProperty("name") String name,
        @NonNull @JsonProperty("displayName") String displayName,
        @NonNull @JsonProperty("id") ByteArray id,
        @JsonProperty("icon") URL icon
    ) {
        this(name, displayName, id, Optional.ofNullable(icon));
    }

}
