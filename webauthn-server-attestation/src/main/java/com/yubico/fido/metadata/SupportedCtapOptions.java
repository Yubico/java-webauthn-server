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
  boolean plat;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean rk;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean clientPin;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean up;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean uv;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonAlias("uvToken")
  boolean pinUvAuthToken;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean noMcGaPermissionsWithClientPin;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean largeBlobs;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean ep;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean bioEnroll;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean userVerificationMgmtPreview;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean uvBioEnroll;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonAlias("config")
  boolean authnrCfg;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean uvAcfg;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean credMgmt;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean credentialMgmtPreview;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean setMinPINLength;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  boolean makeCredUvNotRqd;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  @JsonInclude(JsonInclude.Include.NON_DEFAULT)
  boolean alwaysUv;

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
