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
     * Note: we use "alg" as the latter member name, rather than spelling-out "algorithm", because it will be serialized
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

    /**
     * Algorithm {@link COSEAlgorithmIdentifier#ES256} and type {@link PublicKeyCredentialType#PUBLIC_KEY}.
     */
    public static final PublicKeyCredentialParameters ES256 = builder().alg(COSEAlgorithmIdentifier.ES256).build();

    /**
     * Algorithm {@link COSEAlgorithmIdentifier#RS256} and type {@link PublicKeyCredentialType#PUBLIC_KEY}.
     */
    public static final PublicKeyCredentialParameters RS256 = builder().alg(COSEAlgorithmIdentifier.RS256).build();

}
