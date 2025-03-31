package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.extension.uvm.KeyProtectionType;
import com.yubico.webauthn.extension.uvm.MatcherProtectionType;
import com.yubico.webauthn.extension.uvm.UserVerificationMethod;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/** Definitions for WebAuthn extensions. */
@Slf4j
@UtilityClass
public class Extensions {

  /**
   * Definitions for the FIDO AppID Extension (<code>appid</code>).
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
   *     FIDO AppID Extension (appid)</a>
   */
  public static class Appid {
    static final String EXTENSION_ID = "appid";
  }

  /**
   * Definitions for the 10.2. FIDO AppID Exclusion Extension (<code>appidExclude</code>).
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">10.2.
   *     FIDO AppID Exclusion Extension (appidExclude)</a>
   */
  public static class AppidExclude {
    static final String EXTENSION_ID = "appidExclude";
  }

  /**
   * Definitions for the Credential Properties Extension (<code>credProps</code>).
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
   *     Credential Properties Extension (credProps)</a>
   */
  public static class CredentialProperties {
    static final String EXTENSION_ID = "credProps";

    /**
     * Extension outputs for the Credential Properties Extension (<code>credProps</code>).
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
     *     Credential Properties Extension (credProps)</a>
     */
    @Value
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CredentialPropertiesOutput {
      @JsonProperty("rk")
      private final Boolean rk;

      @JsonCreator
      private CredentialPropertiesOutput(@JsonProperty("rk") Boolean rk) {
        this.rk = rk;
      }

      /**
       * This OPTIONAL property, known abstractly as the <b>resident key credential property</b>
       * (i.e., <b>client-side discoverable credential property</b>), is a Boolean value indicating
       * whether the {@link PublicKeyCredential} returned as a result of a registration ceremony is
       * a <i>client-side discoverable credential</i> (passkey).
       *
       * <p>If this is <code>true</code>, the credential is a <i>discoverable credential</i>
       * (passkey).
       *
       * <p>If this is <code>false</code>, the credential is a <i>server-side credential</i>.
       *
       * <p>If this is not present, it is not known whether the credential is a discoverable
       * credential or a server-side credential.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-credentialpropertiesoutput-rk">§10.4.
       *     Credential Properties Extension (credProps)</a>
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
       *     discoverable Credential</a>
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
       *     Credential</a>
       * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a> in <a
       *     href="https://passkeys.dev">passkeys.dev</a> reference
       */
      public Optional<Boolean> getRk() {
        return Optional.ofNullable(rk);
      }
    }
  }

  /**
   * Definitions for the Credential Protection (<code>credProtect</code>) extension.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
   *     §12.1. Credential Protection (credProtect)</a>
   */
  public static class CredentialProtection {
    static final String EXTENSION_ID = "credProtect";

    /**
     * Policy values for the Credential Protection (<code>credProtect</code>) extension.
     *
     * <p>Available values:
     *
     * <ul>
     *   <li>{@link #UV_OPTIONAL}
     *   <li>{@link #UV_OPTIONAL_WITH_CREDENTIAL_ID_LIST}
     *   <li>{@link #UV_REQUIRED}
     * </ul>
     *
     * @see <a
     *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
     *     §12.1. Credential Protection (credProtect)</a>
     * @see CredentialProtectionInput#prefer(CredentialProtectionPolicy)
     * @see CredentialProtectionInput#require(CredentialProtectionPolicy)
     */
    @AllArgsConstructor
    public enum CredentialProtectionPolicy {
      /**
       * In this configuration, performing some form of user verification is always OPTIONAL. This
       * is the default behaviour if the extension is not specified; note however that some browsers
       * may set a different default extension input if the extension is not explicitly specified.
       *
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">User
       *     Verification</a>
       */
      UV_OPTIONAL(0x01, "userVerificationOptional"),

      /**
       * In this configuration, performing some form of user verification is OPTIONAL when the
       * credential is used as the second authentication factor, and REQUIRED when the credential is
       * used as the first authentication factor.
       *
       * <p>In technical terms, user verification is REQUIRED when {@link
       * PublicKeyCredentialRequestOptions#getAllowCredentials() allowCredentials} is empty and
       * OPTIONAL when it is non-empty. {@link
       * PublicKeyCredentialRequestOptions#getAllowCredentials() allowCredentials} is non-empty when
       * {@link StartAssertionOptions.StartAssertionOptionsBuilder#username(String) username} or
       * {@link StartAssertionOptions.StartAssertionOptionsBuilder#userHandle(ByteArray) userHandle}
       * was set in the call to {@link RelyingParty#startAssertion(StartAssertionOptions)}, and is
       * empty when neither was set.
       *
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">User
       *     Verification</a>
       */
      UV_OPTIONAL_WITH_CREDENTIAL_ID_LIST(0x02, "userVerificationOptionalWithCredentialIDList"),

      /**
       * In this configuration, performing some form of user verification is always REQUIRED.
       *
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">User
       *     Verification</a>
       */
      UV_REQUIRED(0x03, "userVerificationRequired");

      final int cborValue;

      @JsonValue private final String jsValue;

      private static Optional<CredentialProtectionPolicy> fromCbor(int cborValue) {
        return Arrays.stream(CredentialProtectionPolicy.values())
            .filter(policy -> policy.cborValue == cborValue)
            .findAny();
      }

      private static Optional<CredentialProtectionPolicy> fromJs(String jsonValue) {
        return Arrays.stream(CredentialProtectionPolicy.values())
            .filter(policy -> policy.jsValue.equals(jsonValue))
            .findAny();
      }

      @JsonCreator
      private static CredentialProtectionPolicy fromJsonString(@NonNull String value) {
        return fromJs(value)
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        String.format(
                            "Unknown %s value: %s",
                            CredentialProtectionPolicy.class.getSimpleName(), value)));
      }
    }

    /**
     * Extension inputs for the Credential Protection (<code>credProtect</code>) extension.
     *
     * <p>Instances may be created using the {@link #prefer(CredentialProtectionPolicy)} and {@link
     * #require(CredentialProtectionPolicy)} factory functions.
     *
     * @see <a
     *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
     *     §12.1. Credential Protection (credProtect)</a>
     */
    @Value
    public static class CredentialProtectionInput {
      /**
       * The requested credential protection policy. This policy may or may not be satisfied; see
       * {@link #isEnforceCredentialProtectionPolicy()}.
       *
       * @see CredentialProtectionPolicy
       * @see #isEnforceCredentialProtectionPolicy()
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       */
      private final CredentialProtectionPolicy credentialProtectionPolicy;

      /**
       * If this is <code>true</code> and {@link #getCredentialProtectionPolicy()
       * credentialProtectionPolicy} is not {@link CredentialProtectionPolicy#UV_OPTIONAL}, {@link
       * RelyingParty#finishRegistration(FinishRegistrationOptions)} will validate that the policy
       * set in {@link #getCredentialProtectionPolicy()} was satisfied and the browser is requested
       * to fail the registration if the policy cannot be satisfied.
       *
       * <p>{@link CredentialProtectionInput#prefer(CredentialProtectionPolicy)} sets this to <code>
       * false</code>. {@link CredentialProtectionInput#require(CredentialProtectionPolicy)} sets
       * this to <code>true</code>.
       *
       * @see CredentialProtectionPolicy
       * @see #getCredentialProtectionPolicy()
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       */
      private final boolean enforceCredentialProtectionPolicy;

      @JsonCreator
      private CredentialProtectionInput(
          @JsonProperty("credentialProtectionPolicy")
              CredentialProtectionPolicy credentialProtectionPolicy,
          @JsonProperty("enforceCredentialProtectionPolicy")
              Boolean enforceCredentialProtectionPolicy) {
        this.credentialProtectionPolicy = credentialProtectionPolicy;
        this.enforceCredentialProtectionPolicy =
            enforceCredentialProtectionPolicy != null && enforceCredentialProtectionPolicy;
      }

      /**
       * Create a Credential Protection (<code>credProtect</code>) extension input that requests the
       * given policy when possible.
       *
       * <p>If the policy cannot be satisfied, the browser is requested to continue the registration
       * anyway. To determine what policy was applied, use {@link
       * AuthenticatorRegistrationExtensionOutputs#getCredProtect()} to inspect the extension
       * output. {@link RelyingParty#finishRegistration(FinishRegistrationOptions)} will not
       * validate what policy was applied.
       *
       * <p>Use {@link #require(CredentialProtectionPolicy)} instead to forbid the registration from
       * proceeding if the extension is not supported or the policy cannot be satisfied.
       *
       * @param policy the policy to request.
       * @return a <code>credProtect</code> extension input that requests the given policy when
       *     possible. The browser is requested to continue the registration even if this policy
       *     cannot be satisfied.
       * @see #require(CredentialProtectionPolicy)
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       */
      public static CredentialProtectionInput prefer(
          @NonNull final CredentialProtectionPolicy policy) {
        return new CredentialProtectionInput(policy, false);
      }

      /**
       * Create a Credential Protection (<code>credProtect</code>) extension input that requires the
       * given policy.
       *
       * <p>If the policy is not {@link CredentialProtectionPolicy#UV_OPTIONAL} and cannot be
       * satisfied, the browser is requested to abort the registration instead of proceeding. {@link
       * RelyingParty#finishRegistration(FinishRegistrationOptions)} will validate that the policy
       * returned in the authenticator extension output equals this input policy, and throw an
       * exception otherwise. You can also use {@link
       * AuthenticatorRegistrationExtensionOutputs#getCredProtect()} to inspect the extension output
       * yourself.
       *
       * <p>Note that if the browser or authenticator does not support the extension, the
       * registration will fail. Use {@link #prefer(CredentialProtectionPolicy)} instead to allow
       * the registration to proceed if the extension is not supported or the policy cannot be
       * satisfied.
       *
       * @param policy the policy to require.
       * @return a <code>credProtect</code> extension input that requires the given policy. The
       *     browser is requested to abort the registration if this policy cannot be satisfied.
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
       *     §12.1. Credential Protection (credProtect)</a>
       */
      public static CredentialProtectionInput require(
          @NonNull final CredentialProtectionPolicy policy) {
        return new CredentialProtectionInput(policy, true);
      }
    }

    /**
     * Validate that the given response satisfies the <code>credProtect</code> extension policy set
     * in the request.
     *
     * <p>If the {@link
     * RegistrationExtensionInputs.RegistrationExtensionInputsBuilder#credProtect(CredentialProtectionInput)
     * credProtect} extension is not set in the request, this has no effect.
     *
     * <p>If the {@link
     * RegistrationExtensionInputs.RegistrationExtensionInputsBuilder#credProtect(CredentialProtectionInput)
     * credProtect} extension is set in the request with {@link
     * CredentialProtectionInput#isEnforceCredentialProtectionPolicy()
     * enforceCredentialProtectionPolicy} set to <code>false</code> or {@link
     * CredentialProtectionInput#getCredentialProtectionPolicy() credentialProtectionPolicy} set to
     * {@link CredentialProtectionPolicy#UV_OPTIONAL}, this has no effect.
     *
     * <p>If the {@link
     * RegistrationExtensionInputs.RegistrationExtensionInputsBuilder#credProtect(CredentialProtectionInput)
     * credProtect} extension is set in the request with {@link
     * CredentialProtectionInput#isEnforceCredentialProtectionPolicy()
     * enforceCredentialProtectionPolicy} set to <code>true</code> and {@link
     * CredentialProtectionInput#getCredentialProtectionPolicy() credentialProtectionPolicy} is not
     * set to {@link CredentialProtectionPolicy#UV_OPTIONAL}, then this throws an {@link
     * IllegalArgumentException} if the <code>credProtect</code> authenticator extension output does
     * not equal the {@link CredentialProtectionInput#getCredentialProtectionPolicy()
     * credentialProtectionPolicy} set in the request.
     *
     * <p>This function is called automatically in {@link
     * RelyingParty#finishRegistration(FinishRegistrationOptions)}; you should not need to call it
     * yourself.
     *
     * @param request the arguments to start the registration ceremony.
     * @param response the response from the registration ceremony.
     * @throws IllegalArgumentException if the {@link
     *     RegistrationExtensionInputs.RegistrationExtensionInputsBuilder#credProtect(CredentialProtectionInput)
     *     credProtect} extension is set in the request with {@link
     *     CredentialProtectionInput#isEnforceCredentialProtectionPolicy()
     *     enforceCredentialProtectionPolicy} set to <code>true</code> and {@link
     *     CredentialProtectionInput#getCredentialProtectionPolicy() credentialProtectionPolicy} not
     *     set to {@link CredentialProtectionPolicy#UV_OPTIONAL}, and the <code>credProtect
     *     </code> authenticator extension output does not equal the {@link
     *     CredentialProtectionInput#getCredentialProtectionPolicy() credentialProtectionPolicy} set
     *     in the request.
     * @see <a
     *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
     *     §12.1. Credential Protection (credProtect)</a>
     */
    public static void validateExtensionOutput(
        PublicKeyCredentialCreationOptions request,
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
            response) {
      request
          .getExtensions()
          .getCredProtect()
          .ifPresent(
              credProtectInput -> {
                if (credProtectInput.isEnforceCredentialProtectionPolicy()
                    && credProtectInput.getCredentialProtectionPolicy()
                        != CredentialProtectionPolicy.UV_OPTIONAL) {
                  Optional<CredentialProtectionPolicy> outputPolicy =
                      response
                          .getResponse()
                          .getParsedAuthenticatorData()
                          .getExtensions()
                          .flatMap(CredentialProtection::parseAuthenticatorExtensionOutput);
                  ExceptionUtil.assertTrue(
                      outputPolicy.equals(
                          Optional.of(credProtectInput.getCredentialProtectionPolicy())),
                      "Unsatisfied credProtect policy: required %s, got: %s",
                      credProtectInput.getCredentialProtectionPolicy(),
                      outputPolicy);
                }
              });
    }

    static Optional<CredentialProtectionPolicy> parseAuthenticatorExtensionOutput(CBORObject cbor) {
      return Optional.ofNullable(cbor.get(EXTENSION_ID))
          .map(
              cborObject ->
                  cborObject.isNumber() && cborObject.AsNumber().IsInteger()
                      ? cborObject.AsInt32()
                      : null)
          .flatMap(CredentialProtectionPolicy::fromCbor);
    }
  }

  /**
   * Definitions for the Large blob storage extension (<code>largeBlob</code>).
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
   *     Large blob storage extension (largeBlob)</a>
   */
  public static class LargeBlob {
    static final String EXTENSION_ID = "largeBlob";

    /**
     * Extension inputs for the Large blob storage extension (<code>largeBlob</code>) in
     * registration ceremonies.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    @Value
    public static class LargeBlobRegistrationInput {
      /**
       * The Relying Party's preference of whether the created credential should support the <code>
       * largeBlob</code> extension.
       */
      @JsonProperty private final LargeBlobSupport support;

      @JsonCreator
      public LargeBlobRegistrationInput(
          /**
           * The Relying Party's preference of whether the created credential should support the
           * <code>
           * largeBlob</code> extension.
           *
           * <p>Currently the only valid values are {@link LargeBlobSupport#REQUIRED} and {@link
           * LargeBlobSupport#PREFERRED}, but custom values MAY be constructed in case more values
           * are added in future revisions of the extension.
           */
          @JsonProperty("support") LargeBlobSupport support) {
        this.support = support;
      }

      /**
       * The known valid arguments for the Large blob storage extension (<code>largeBlob</code>)
       * input in registration ceremonies.
       *
       * <p>Currently the only valid values are {@link LargeBlobSupport#REQUIRED} and {@link
       * LargeBlobSupport#PREFERRED}, but custom values MAY be constructed in case more values are
       * added in future revisions of the extension.
       *
       * @see #REQUIRED
       * @see #PREFERRED
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      @Value
      public static class LargeBlobSupport {
        /**
         * The authenticator used for registration MUST support the <code>largeBlob</code>
         * extension.
         *
         * <p>Note: If the client does not support the <code>largeBlob</code> extension, this
         * requirement MAY be ignored.
         *
         * <p>Note: CTAP authenticators only support <code>largeBlob</code> in combination with
         * {@link AuthenticatorSelectionCriteria#getResidentKey()} set to <code>REQUIRED</code> in
         * {@link StartRegistrationOptions#getAuthenticatorSelection()}.
         *
         * @see <a
         *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
         *     Large blob storage extension (largeBlob)</a>
         */
        public static final LargeBlobSupport REQUIRED = new LargeBlobSupport("required");

        /**
         * If the authenticator used for registration supports the <code>largeBlob</code> extension,
         * it will be enabled for the created credential. If not supported, the credential will be
         * created without large blob support.
         *
         * <p>Note: CTAP authenticators only support <code>largeBlob</code> in combination with
         * {@link AuthenticatorSelectionCriteria#getResidentKey()} set to <code>REQUIRED</code> in
         * {@link StartRegistrationOptions#getAuthenticatorSelection()}.
         *
         * @see <a
         *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
         *     Large blob storage extension (largeBlob)</a>
         */
        public static final LargeBlobSupport PREFERRED = new LargeBlobSupport("preferred");

        /**
         * The underlying string value of this {@link LargeBlobSupport} value.
         *
         * @see #REQUIRED
         * @see #PREFERRED
         */
        @JsonValue private final String value;

        /**
         * Returns a new {@link Set} containing the {@link #REQUIRED} and {@link #PREFERRED} values.
         */
        public static Set<LargeBlobSupport> values() {
          return Stream.of(REQUIRED, PREFERRED).collect(Collectors.toSet());
        }
      }
    }

    /**
     * Extension inputs for the Large blob storage extension (<code>largeBlob</code>) in
     * authentication ceremonies.
     *
     * <p>Use the {@link #read()} and {@link #write(ByteArray)} factory functions to construct this
     * type.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    @Value
    public static class LargeBlobAuthenticationInput {
      /**
       * If <code>true</code>, indicates that the Relying Party would like to fetch the
       * previously-written blob associated with the asserted credential.
       *
       * @see #read()
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargeblobinputs-read">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      @JsonProperty private final boolean read;

      /**
       * An opaque byte string that the Relying Party wishes to store with the existing credential.
       *
       * @see #write(ByteArray)
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargeblobinputs-write">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      @JsonProperty private final ByteArray write;

      @JsonCreator
      private LargeBlobAuthenticationInput(
          @JsonProperty("read") final Boolean read, @JsonProperty("write") final ByteArray write) {
        if (read != null && read && write != null) {
          throw new IllegalArgumentException(
              "Parameters \"read\" and \"write\" of largeBlob extension must not both be present.");
        }

        this.read = read != null && read;
        this.write = write;
      }

      /**
       * Configure the Large blob storage extension (<code>largeBlob</code>) to fetch the
       * previously-written blob associated with the asserted credential.
       *
       * <p>Mutually exclusive with {@link #write(ByteArray)}.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargeblobinputs-read">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public static LargeBlobAuthenticationInput read() {
        return new LargeBlobAuthenticationInput(true, null);
      }

      /**
       * Configure the Large blob storage extension (<code>largeBlob</code>) to store the given byte
       * array with the existing credential.
       *
       * <p>Mutually exclusive with {@link #read()}.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargeblobinputs-write">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public static LargeBlobAuthenticationInput write(@NonNull final ByteArray write) {
        return new LargeBlobAuthenticationInput(false, write);
      }

      /**
       * @return <code>true</code> if the <code>read</code> property is set to <code>true</code>,
       *     <code>false</code> otherwise.
       * @see #read()
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargeblobinputs-read">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public boolean getRead() {
        return read;
      }

      /**
       * @return The value of the <code>write</code> property if configured, empty otherwise.
       * @see #write(ByteArray)
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargeblobinputs-read">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public Optional<ByteArray> getWrite() {
        return Optional.ofNullable(write);
      }
    }

    /**
     * Extension outputs for the Large blob storage extension (<code>largeBlob</code>) in
     * registration ceremonies.
     *
     * <p>Use the {@link #supported(boolean)} factory function to construct this type.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    @Value
    public static class LargeBlobRegistrationOutput {
      /**
       * <code>true</code> if, and only if, the created credential supports storing large blobs.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargebloboutputs-supported">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       * @see LargeBlobRegistrationInput#getSupport()
       */
      @JsonProperty private final boolean supported;

      @JsonCreator
      private LargeBlobRegistrationOutput(@JsonProperty("supported") boolean supported) {
        this.supported = supported;
      }

      /**
       * Create a Large blob storage extension output with the <code>supported</code> output set to
       * the given value.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-authenticationextensionslargebloboutputs">
       *     dictionary AuthenticationExtensionsLargeBlobOutputs</a>
       */
      public static LargeBlobRegistrationOutput supported(boolean supported) {
        return new LargeBlobRegistrationOutput(supported);
      }
    }

    /**
     * Extension outputs for the Large blob storage extension (<code>largeBlob</code>) in
     * authentication ceremonies.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    @Value
    public static class LargeBlobAuthenticationOutput {
      @JsonProperty private final ByteArray blob;
      @JsonProperty private final Boolean written;

      @JsonCreator
      private LargeBlobAuthenticationOutput(
          @JsonProperty("blob") ByteArray blob, @JsonProperty("written") Boolean written) {
        this.blob = blob;
        this.written = written;
      }

      /**
       * Create a Large blob storage extension output with the <code>blob</code> output set to the
       * given value.
       *
       * <p>This corresponds to the extension input {@link LargeBlobAuthenticationInput#read()
       * LargeBlobAuthenticationInput.read()}.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-authenticationextensionslargebloboutputs">
       *     dictionary AuthenticationExtensionsLargeBlobOutputs</a>
       */
      public static LargeBlobAuthenticationOutput read(final ByteArray blob) {
        return new LargeBlobAuthenticationOutput(blob, null);
      }

      /**
       * Create a Large blob storage extension output with the <code>written</code> output set to
       * the given value.
       *
       * <p>This corresponds to the extension input {@link
       * LargeBlobAuthenticationInput#write(ByteArray)
       * LargeBlobAuthenticationInput.write(ByteArray)}.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-authenticationextensionslargebloboutputs">
       *     dictionary AuthenticationExtensionsLargeBlobOutputs</a>
       */
      public static LargeBlobAuthenticationOutput write(final boolean write) {
        return new LargeBlobAuthenticationOutput(null, write);
      }

      /**
       * The opaque byte string that was associated with the credential identified by {@link
       * PublicKeyCredential#getId()}. Only valid if {@link LargeBlobAuthenticationInput#getRead()}
       * was <code>true</code>.
       *
       * @return A present {@link Optional} if {@link LargeBlobAuthenticationInput#getRead()} was
       *     <code>true</code> and the blob content was successfully read. Otherwise (if {@link
       *     LargeBlobAuthenticationInput#getRead()} was <code>false</code> or the content failed to
       *     be read) an empty {@link Optional}.
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargebloboutputs-blob">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public Optional<ByteArray> getBlob() {
        return Optional.ofNullable(blob);
      }

      /**
       * A boolean that indicates that the contents of {@link
       * LargeBlob.LargeBlobAuthenticationInput#write(ByteArray)
       * LargeBlobAuthenticationInput#write(ByteArray)} were successfully stored on the
       * authenticator, associated with the specified credential.
       *
       * @return Empty if {@link LargeBlobAuthenticationInput#getWrite()} was not present. Otherwise
       *     <code>true</code> if and only if the value of {@link
       *     LargeBlobAuthenticationInput#getWrite()} was successfully stored by the authenticator.
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargebloboutputs-written">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public Optional<Boolean> getWritten() {
        return Optional.ofNullable(written);
      }
    }
  }

  /**
   * Definitions for the Pseudo-random function extension (<code>prf</code>).
   *
   * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random function
   *     extension (prf)</a>
   */
  public static class Prf {
    static final String EXTENSION_ID = "prf";

    /**
     * The known valid arguments for the Pseudo-random function extension (<code>prf</code>) input
     * in registration and authentication ceremonies.
     *
     * <p>
     *
     * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
     *     function extension (prf)</a>
     */
    @Value
    public static class PrfValues {
      /** */
      @JsonProperty @NonNull public final ByteArray first;

      @JsonProperty public final ByteArray second;

      @JsonCreator
      public PrfValues(
          @JsonProperty("first") @NonNull final ByteArray first,
          @JsonProperty("second") final ByteArray second) {
        this.first = first;
        this.second = second;
      }

      public Optional<ByteArray> getSecond() {
        return Optional.ofNullable(second);
      }
    }

    /**
     * Extension inputs for the Pseudo-random function extension (<code>prf</code>) in
     * authentication ceremonies.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
     *     function extension (prf)</a>
     */
    @Value
    public static class PrfAuthenticationInput {
      /** */
      @JsonProperty private final PrfValues eval;

      @JsonProperty private final Map<ByteArray, PrfValues> evalByCredential;

      @JsonCreator
      public PrfAuthenticationInput(
          @JsonProperty("eval") PrfValues eval,
          @JsonProperty("evalByCredential") Map<ByteArray, PrfValues> evalByCredential) {
        this.eval = eval;
        this.evalByCredential = evalByCredential;
      }

      public Optional<PrfValues> getEval() {
        return Optional.ofNullable(eval);
      }

      public Optional<Map<ByteArray, PrfValues>> getEvalByCredential() {
        return Optional.ofNullable(evalByCredential);
      }

      static HashMap<ByteArray, PrfValues> descriptorsToIds(
          Map<PublicKeyCredentialDescriptor, PrfValues> evalByCredential) {
        return evalByCredential.entrySet().stream()
            .reduce(
                new HashMap<>(),
                (ebc, entry) -> {
                  ebc.put(entry.getKey().getId(), entry.getValue());
                  return ebc;
                },
                (a, b) -> {
                  a.putAll(b);
                  return a;
                });
      }
    }

    /**
     * Extension inputs for the Pseudo-random function extension (<code>prf</code>) in registration
     * ceremonies.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
     *     function extension (prf)</a>
     */
    @Value
    public static class PrfRegistrationInput {
      /** */
      @JsonProperty private final PrfValues eval;

      @JsonCreator
      public PrfRegistrationInput(@JsonProperty("eval") PrfValues eval) {
        this.eval = eval;
      }

      public Optional<PrfValues> getEval() {
        return Optional.ofNullable(eval);
      }
    }

    /**
     * Extension outputs for the Pseudo-random function extension (<code>prf</code>) in registration
     * ceremonies.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
     *     function extension (prf)</a>
     */
    @Value
    public static class PrfRegistrationOutput {

      /**
       * <code>true</code> if, and only if, the one or two PRFs are available for use with the
       * created credential.
       *
       * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
       *     function extension (prf)</a>
       */
      @JsonProperty private final boolean enabled;

      /**
       * The results of evaluating the PRF for the inputs given in eval or evalByCredential.
       *
       * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
       *     function extension (prf)</a>
       */
      @JsonProperty private final PrfValues results;

      @JsonCreator
      private PrfRegistrationOutput(
          @JsonProperty("enabled") boolean enabled, @JsonProperty("results") PrfValues results) {
        this.enabled = enabled;
        this.results = results;
      }

      /** TODO */
      public static PrfRegistrationOutput enabled(final boolean enabled) {
        return new PrfRegistrationOutput(enabled, null);
      }

      /** TODO */
      public static PrfRegistrationOutput results(final PrfValues results) {
        return new PrfRegistrationOutput(true, results);
      }

      public Optional<Boolean> getEnabled() {
        return Optional.of(enabled);
      }

      public Optional<PrfValues> getResults() {
        return Optional.ofNullable(results);
      }
    }

    /**
     * Extension outputs for the Large blob storage extension (<code>largeBlob</code>) in
     * authentication ceremonies.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
     *     function extension (prf)</a>
     */
    @Value
    public static class PrfAuthenticationOutput {

      /**
       * The results of evaluating the PRF for the inputs given in eval or evalByCredential.
       *
       * @see <a href="https://www.w3.org/TR/webauthn-3/#prf-extension">§10.1.4. Pseudo-random
       *     function extension (prf)</a>
       */
      @JsonProperty private final PrfValues results;

      @JsonCreator
      private PrfAuthenticationOutput(@JsonProperty("results") PrfValues results) {
        this.results = results;
      }

      public static PrfAuthenticationOutput results(final PrfValues results) {
        return new PrfAuthenticationOutput(results);
      }

      /**
       * @return A present {@link Optional} if {@link LargeBlobAuthenticationInput#getRead()} was
       *     <code>true</code> and the blob content was successfully read. Otherwise (if {@link
       *     LargeBlobAuthenticationInput#getRead()} was <code>false</code> or the content failed to
       *     be read) an empty {@link Optional}.
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticationextensionslargebloboutputs-blob">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public Optional<PrfValues> getResults() {
        return Optional.ofNullable(results);
      }
    }
  }

  /**
   * Definitions for the User Verification Method (<code>uvm</code>) Extension.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
   *     User Verification Method Extension (uvm)</a>
   */
  public static class Uvm {
    static final String EXTENSION_ID = "uvm";

    /**
     * A <code>uvmEntry</code> as defined in <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3. User
     * Verification Method Extension (uvm)</a>.
     *
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
     *     User Verification Method Extension (uvm)</a>
     * @see UserVerificationMethod
     * @see KeyProtectionType
     * @see MatcherProtectionType
     */
    @Value
    public static class UvmEntry {
      private final UserVerificationMethod userVerificationMethod;
      private final KeyProtectionType keyProtectionType;
      private final MatcherProtectionType matcherProtectionType;

      public UvmEntry(
          @JsonProperty("userVerificationMethod") UserVerificationMethod userVerificationMethod,
          @JsonProperty("keyProtectionType") KeyProtectionType keyProtectionType,
          @JsonProperty("matcherProtectionType") MatcherProtectionType matcherProtectionType) {
        this.userVerificationMethod = userVerificationMethod;
        this.keyProtectionType = keyProtectionType;
        this.matcherProtectionType = matcherProtectionType;
      }
    }

    static Optional<List<UvmEntry>> parseAuthenticatorExtensionOutput(CBORObject cbor) {
      if (validateAuthenticatorExtensionOutput(cbor)) {
        return Optional.of(
            cbor.get(EXTENSION_ID).getValues().stream()
                .map(
                    uvmEntry ->
                        new UvmEntry(
                            UserVerificationMethod.fromValue(uvmEntry.get(0).AsInt32Value()),
                            KeyProtectionType.fromValue(
                                uvmEntry.get(1).AsNumber().ToInt16IfExact()),
                            MatcherProtectionType.fromValue(
                                uvmEntry.get(2).AsNumber().ToInt16IfExact())))
                .collect(Collectors.toList()));
      } else {
        return Optional.empty();
      }
    }

    private static boolean validateAuthenticatorExtensionOutput(CBORObject extensions) {
      if (!extensions.ContainsKey(EXTENSION_ID)) {
        return false;
      }

      CBORObject uvm = extensions.get(EXTENSION_ID);
      if (uvm.getType() != CBORType.Array) {
        log.debug(
            "Invalid CBOR type for \"{}\" extension output: expected array, was: {}",
            EXTENSION_ID,
            uvm.getType());
        return false;
      }

      if (uvm.size() < 1 || uvm.size() > 3) {
        log.debug(
            "Invalid length \"{}\" extension output array: expected 1 to 3 (inclusive), was: {}",
            EXTENSION_ID,
            uvm.size());
        return false;
      }

      for (CBORObject entry : uvm.getValues()) {
        if (entry.getType() != CBORType.Array) {
          log.debug("Invalid CBOR type for uvmEntry: expected array, was: {}", entry.getType());
          return false;
        }

        if (entry.size() != 3) {
          log.debug("Invalid length for uvmEntry: expected 3, was: {}", entry.size());
          return false;
        }

        for (CBORObject i : entry.getValues()) {
          if (!(i.isNumber() && i.AsNumber().IsInteger())) {
            log.debug("Invalid type for uvmEntry element: expected integer, was: {}", i.getType());
            return false;
          }
        }
      }

      return true;
    }
  }
}
