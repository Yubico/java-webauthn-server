package com.yubico.webauthn;

import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;

/**
 * A type that can be converted into a {@link PublicKeyCredentialDescriptor} value.
 *
 * @see PublicKeyCredentialDescriptor
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialdescriptor">§5.10.3.
 *     Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
 * @see CredentialRecord
 * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
 *     before reaching a mature release.
 */
@Deprecated
public interface ToPublicKeyCredentialDescriptor {

  /**
   * Convert this value to a {@link PublicKeyCredentialDescriptor} value.
   *
   * <p>Implementations MUST NOT return null.
   *
   * @see PublicKeyCredentialDescriptor
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialdescriptor">§5.10.3.
   *     Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
   * @see CredentialRecord
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  PublicKeyCredentialDescriptor toPublicKeyCredentialDescriptor();
}
