package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.AssertionResultV2;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.extension.uvm.KeyProtectionType;
import com.yubico.webauthn.extension.uvm.MatcherProtectionType;
import com.yubico.webauthn.extension.uvm.UserVerificationMethod;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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

      @JsonProperty("authenticatorDisplayName")
      private final String authenticatorDisplayName;

      @JsonCreator
      private CredentialPropertiesOutput(
          @JsonProperty("rk") Boolean rk,
          @JsonProperty("authenticatorDisplayName") String authenticatorDisplayName) {
        this.rk = rk;
        this.authenticatorDisplayName = authenticatorDisplayName;
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

      /**
       * This OPTIONAL property is a human-palatable description of the credential's managing
       * authenticator, chosen by the user.
       *
       * <p>If the application supports setting "nicknames" for registered credentials, then this
       * value may be a suitable default value for such a nickname.
       *
       * <p>In an authentication ceremony, if this value is different from the stored nickname, then
       * the application may want to offer the user to update the stored nickname to match this
       * value.
       *
       * @return A user-chosen or vendor-default display name for the credential, if available.
       *     Otherwise empty.
       * @see <a
       *     href="https://w3c.github.io/webauthn/#dom-credentialpropertiesoutput-authenticatordisplayname">
       *     <code>authenticatorDisplayName</code> in §10.1.3. Credential Properties Extension
       *     (credProps)</a>
       * @see RegistrationResult#getAuthenticatorDisplayName()
       * @see AssertionResult#getAuthenticatorDisplayName()
       * @see AssertionResultV2#getAuthenticatorDisplayName()
       * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change
       *     as the standard matures.
       */
      @Deprecated
      public Optional<String> getAuthenticatorDisplayName() {
        return Optional.ofNullable(authenticatorDisplayName);
      }
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
