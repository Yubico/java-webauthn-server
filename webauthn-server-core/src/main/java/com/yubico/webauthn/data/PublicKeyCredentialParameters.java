package com.yubico.webauthn.data;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * Used to supply additional parameters when creating a new credential.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class PublicKeyCredentialParameters {

    /**
     * Specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus
     * also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
     *
     * @note we use "alg" as the latter member name, rather than spelling-out "algorithm", because it will be serialized
     * into a message to the authenticator, which may be sent over a low-bandwidth link.
     */
    @NonNull
    private final COSEAlgorithmIdentifier alg;

    /**
     * Specifies the type of credential to be created.
     */
    @NonNull
    @Builder.Default
    private final PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;

}
