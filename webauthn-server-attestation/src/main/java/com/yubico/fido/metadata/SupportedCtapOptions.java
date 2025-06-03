package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Value;

/**
 * A fixed-keys map of CTAP2 option names to Boolean values representing whether an authenticator
 * supports the respective option.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
 *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
 */
@Value
@Builder
public class SupportedCtapOptions {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean plat = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean rk = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean clientPin = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean up = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean uv = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonAlias("uvToken")
  @Builder.Default
  boolean pinUvAuthToken = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean noMcGaPermissionsWithClientPin = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean largeBlobs = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean ep = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean bioEnroll = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean userVerificationMgmtPreview = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean uvBioEnroll = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonAlias("config")
  @Builder.Default
  boolean authnrCfg = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean uvAcfg = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean credMgmt = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean credentialMgmtPreview = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean setMinPINLength = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @Builder.Default boolean makeCredUvNotRqd = false;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  @Builder.Default
  boolean alwaysUv = false;

  @JsonCreator
  private SupportedCtapOptions(
      @JsonProperty("plat") Boolean plat,
      @JsonProperty("rk") Boolean rk,
      @JsonProperty("clientPin") Boolean clientPin,
      @JsonProperty("up") Boolean up,
      @JsonProperty("uv") Boolean uv,
      @JsonProperty("pinUvAuthToken") Boolean pinUvAuthToken,
      @JsonProperty("noMcGaPermissionsWithClientPin") Boolean noMcGaPermissionsWithClientPin,
      @JsonProperty("largeBlobs") Boolean largeBlobs,
      @JsonProperty("ep") Boolean ep,
      @JsonProperty("bioEnroll") Boolean bioEnroll,
      @JsonProperty("userVerificationMgmtPreview") Boolean userVerificationMgmtPreview,
      @JsonProperty("uvBioEnroll") Boolean uvBioEnroll,
      @JsonProperty("authnrCfg") Boolean authnrCfg,
      @JsonProperty("uvAcfg") Boolean uvAcfg,
      @JsonProperty("credMgmt") Boolean credMgmt,
      @JsonProperty("credentialMgmtPreview") Boolean credentialMgmtPreview,
      @JsonProperty("setMinPINLength") Boolean setMinPINLength,
      @JsonProperty("makeCredUvNotRqd") Boolean makeCredUvNotRqd,
      @JsonProperty("alwaysUv") Boolean alwaysUv) {
    this.plat = Boolean.TRUE.equals(plat);
    this.rk = Boolean.TRUE.equals(rk);
    this.clientPin = clientPin != null;
    this.up = Boolean.TRUE.equals(up);
    this.uv = uv != null;
    this.pinUvAuthToken = Boolean.TRUE.equals(pinUvAuthToken);
    this.noMcGaPermissionsWithClientPin = Boolean.TRUE.equals(noMcGaPermissionsWithClientPin);
    this.largeBlobs = Boolean.TRUE.equals(largeBlobs);
    this.ep = ep != null;
    this.bioEnroll = bioEnroll != null;
    this.userVerificationMgmtPreview = userVerificationMgmtPreview != null;
    this.uvBioEnroll = Boolean.TRUE.equals(uvBioEnroll);
    this.authnrCfg = Boolean.TRUE.equals(authnrCfg);
    this.uvAcfg = Boolean.TRUE.equals(uvAcfg);
    this.credMgmt = Boolean.TRUE.equals(credMgmt);
    this.credentialMgmtPreview = Boolean.TRUE.equals(credentialMgmtPreview);
    this.setMinPINLength = Boolean.TRUE.equals(setMinPINLength);
    this.makeCredUvNotRqd = Boolean.TRUE.equals(makeCredUvNotRqd);
    this.alwaysUv = alwaysUv != null;
  }
}
