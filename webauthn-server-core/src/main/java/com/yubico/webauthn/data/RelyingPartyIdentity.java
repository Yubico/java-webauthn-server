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
 * Describes a Relying Party with which a public key credential is associated.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class RelyingPartyIdentity implements PublicKeyCredentialEntity {

    /**
     * The human-friendly name of the Relaying Party.
     *
     * For example: "Acme Corporation", "Widgets, Inc.", or "Awesome Site".
     */
    @NonNull
    private final String name;

    /**
     * The RP identifier with which credentials are associated.
     */
    @NonNull
    private final String id;

    /**
     * A URL which resolves to an image associated with the RP.
     *
     * For example, this could be the RP's logo.
     */
    @NonNull
    @Builder.Default
    private final Optional<URL> icon = Optional.empty();

    @JsonCreator
    private RelyingPartyIdentity(
        @NonNull @JsonProperty("name") String name,
        @NonNull @JsonProperty("id") String id,
        @JsonProperty("icon") URL icon
    ) {
        this(name, id, Optional.ofNullable(icon));
    }

}
