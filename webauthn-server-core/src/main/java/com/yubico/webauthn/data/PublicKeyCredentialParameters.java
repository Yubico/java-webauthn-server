package com.yubico.webauthn.data;

import lombok.NonNull;
import lombok.Value;


/**
 * Used to supply additional parameters when creating a new credential.
 */
@Value
public class PublicKeyCredentialParameters {

    /**
     * Specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus
     * also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
     *
     * @note we use "alg" as the latter member name, rather than spelling-out "algorithm", because it will be serialized
     * into a message to the authenticator, which may be sent over a low-bandwidth link.
     */
    private COSEAlgorithmIdentifier alg;

    /**
     * Specifies the type of credential to be created.
     */
    private PublicKeyCredentialType type;

    public PublicKeyCredentialParameters(@NonNull COSEAlgorithmIdentifier alg) {
        this(alg, PublicKeyCredentialType.PUBLIC_KEY);
    }

    public PublicKeyCredentialParameters(@NonNull COSEAlgorithmIdentifier alg, @NonNull PublicKeyCredentialType type) {
        this.alg = alg;
        this.type = type;
    }

}
