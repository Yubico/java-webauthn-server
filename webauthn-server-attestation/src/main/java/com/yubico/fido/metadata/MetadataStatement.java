package com.yubico.fido.metadata;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.extension.uvm.KeyProtectionType;
import com.yubico.webauthn.extension.uvm.MatcherProtectionType;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * Relying Parties can learn a subset of verifiable information for authenticators certified by the
 * FIDO Alliance with an Authenticator Metadata statement. The Metadata statement can be acquired
 * from the Metadata BLOB that is hosted on the Metadata Service [<a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biblio-fidometadataservice">FIDOMetadataService</a>].
 *
 * <p>This class does not include the field <code>ecdaaTrustAnchors</code> since ECDAA is deprecated
 * in WebAuthn Level 2.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
 *     Metadata Statement</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class MetadataStatement {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  String legalHeader;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  AAID aaid;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  AAGUID aaguid;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  Set<String> attestationCertificateKeyIdentifiers;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  String description;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  AlternativeDescriptions alternativeDescriptions;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  long authenticatorVersion;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull ProtocolFamily protocolFamily;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  int schema;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<Version> upv;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<AuthenticationAlgorithm> authenticationAlgorithms;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<AuthenticatorAttestationType> attestationTypes;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<Set<VerificationMethodDescriptor>> userVerificationDetails;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<KeyProtectionType> keyProtection;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  Boolean isKeyRestricted;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  Boolean isFreshUserVerificationRequired;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<MatcherProtectionType> matcherProtection;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  Integer cryptoStrength;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  Set<AttachmentHint> attachmentHint;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull Set<TransactionConfirmationDisplayType> tcDisplay;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  String tcDisplayContentType;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  @NonNull
  @JsonDeserialize(contentConverter = CertFromBase64Converter.class)
  @JsonSerialize(contentConverter = CertToBase64Converter.class)
  Set<X509Certificate> attestationRootCertificates;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  String icon;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  Set<ExtensionDescriptor> supportedExtensions;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  AuthenticatorGetInfo authenticatorGetInfo;

  public MetadataStatement(
      String legalHeader,
      AAID aaid,
      AAGUID aaguid,
      Set<String> attestationCertificateKeyIdentifiers,
      String description,
      AlternativeDescriptions alternativeDescriptions,
      long authenticatorVersion,
      @NonNull ProtocolFamily protocolFamily,
      int schema,
      @NonNull Set<Version> upv,
      @NonNull Set<AuthenticationAlgorithm> authenticationAlgorithms,
      @NonNull Set<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings,
      @NonNull Set<AuthenticatorAttestationType> attestationTypes,
      @NonNull Set<Set<VerificationMethodDescriptor>> userVerificationDetails,
      @NonNull Set<KeyProtectionType> keyProtection,
      Boolean isKeyRestricted,
      Boolean isFreshUserVerificationRequired,
      @NonNull Set<MatcherProtectionType> matcherProtection,
      Integer cryptoStrength,
      Set<AttachmentHint> attachmentHint,
      @NonNull Set<TransactionConfirmationDisplayType> tcDisplay,
      String tcDisplayContentType,
      List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics,
      @NonNull Set<X509Certificate> attestationRootCertificates,
      String icon,
      Set<ExtensionDescriptor> supportedExtensions,
      AuthenticatorGetInfo authenticatorGetInfo) {
    this.legalHeader = legalHeader;
    this.aaid = aaid;
    this.aaguid = aaguid;
    this.attestationCertificateKeyIdentifiers =
        CollectionUtil.immutableSetOrEmpty(attestationCertificateKeyIdentifiers);
    this.description = description;
    this.alternativeDescriptions = alternativeDescriptions;
    this.authenticatorVersion = authenticatorVersion;
    this.protocolFamily = protocolFamily;
    this.schema = schema;
    this.upv = upv;
    this.authenticationAlgorithms = authenticationAlgorithms;
    this.publicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
    this.attestationTypes = attestationTypes;
    this.userVerificationDetails = userVerificationDetails;
    this.keyProtection = keyProtection;
    this.isKeyRestricted = isKeyRestricted;
    this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
    this.matcherProtection = matcherProtection;
    this.cryptoStrength = cryptoStrength;
    this.attachmentHint = attachmentHint;
    this.tcDisplay = tcDisplay;
    this.tcDisplayContentType = tcDisplayContentType;
    this.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
    this.attestationRootCertificates = attestationRootCertificates;
    this.icon = icon;
    this.supportedExtensions = supportedExtensions;
    this.authenticatorGetInfo = authenticatorGetInfo;
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<String> getLegalHeader() {
    return Optional.ofNullable(this.legalHeader);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<AAID> getAaid() {
    return Optional.ofNullable(this.aaid);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<AAGUID> getAaguid() {
    return Optional.ofNullable(this.aaguid);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<String> getDescription() {
    return Optional.ofNullable(this.description);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<AlternativeDescriptions> getAlternativeDescriptions() {
    return Optional.ofNullable(this.alternativeDescriptions);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<Boolean> getIsKeyRestricted() {
    return Optional.ofNullable(this.isKeyRestricted);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<Boolean> getIsFreshUserVerificationRequired() {
    return Optional.ofNullable(this.isFreshUserVerificationRequired);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<Integer> getCryptoStrength() {
    return Optional.ofNullable(this.cryptoStrength);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<Set<AttachmentHint>> getAttachmentHint() {
    return Optional.ofNullable(this.attachmentHint);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<String> getTcDisplayContentType() {
    return Optional.ofNullable(this.tcDisplayContentType);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<List<DisplayPNGCharacteristicsDescriptor>> getTcDisplayPNGCharacteristics() {
    return Optional.ofNullable(this.tcDisplayPNGCharacteristics);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<String> getIcon() {
    return Optional.ofNullable(this.icon);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<Set<ExtensionDescriptor>> getSupportedExtensions() {
    return Optional.ofNullable(this.supportedExtensions);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-statement-format">FIDO
   *     Metadata Statement</a>
   */
  public Optional<AuthenticatorGetInfo> getAuthenticatorGetInfo() {
    return Optional.ofNullable(this.authenticatorGetInfo);
  }
}
