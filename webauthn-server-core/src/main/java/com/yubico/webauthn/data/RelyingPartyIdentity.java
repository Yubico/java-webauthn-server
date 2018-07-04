package com.yubico.webauthn.data;

import java.net.URL;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * Describes a Relying Party with which a public key credential is associated.
 */
@Value
@Builder(toBuilder = true)
public class RelyingPartyIdentity implements PublicKeyCredentialEntity {

    /**
     * The human-friendly name of the Relaying Party.
     *
     * For example: "Acme Corporation", "Widgets, Inc.", or "Awesome Site".
     */
    private String name;

    /**
     * The RP identifier with which credentials are associated.
     */
    private String id;

    /**
     * A URL which resolves to an image associated with the RP.
     *
     * For example, this could be the RP's logo.
     */
    @Builder.Default
    private Optional<URL> icon = Optional.empty();

    private RelyingPartyIdentity(
        @NonNull String name,
        @NonNull String id,
        @NonNull Optional<URL> icon
    ) {
        this.name = name;
        this.id = id;
        this.icon = icon;
    }

}
