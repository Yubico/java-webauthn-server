package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.yubico.webauthn.StartRegistrationOptions;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.Value;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
public class Extensions {

  public static class Appid {
    public static final String EXTENSION_ID = "appid";
  }

  public static class AppidExclude {
    public static final String EXTENSION_ID = "appidExclude";
  }

  /**
   * Definitions for the Credential Properties Extension (<code>credProps</code>).
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
   *     Credential Properties Extension (credProps)</a>
   */
  public static class CredentialProperties {
    public static final String EXTENSION_ID = "credProps";

    /**
     * Extension outputs for the Credential Properties Extension (<code>credProps</code>).
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
     *     Credential Properties Extension (credProps)</a>
     */
    @Value
    public static class CredentialPropertiesOutput {
      @JsonProperty("rk")
      private final Boolean rk;

      @JsonCreator
      CredentialPropertiesOutput(@JsonProperty("rk") Boolean rk) {
        this.rk = rk;
      }

      /**
       * This OPTIONAL property, known abstractly as the <b>resident key credential property</b>
       * (i.e., <b>client-side discoverable credential property</b>), is a Boolean value indicating
       * whether the {@link PublicKeyCredential} returned as a result of a registration ceremony is
       * a <i>client-side discoverable credential</i>.
       *
       * <p>If this is <code>true</code>, the credential is a <i>discoverable credential</i>.
       *
       * <p>If this is <code>false</code>, the credential is a <i>server-side credential</i>.
       *
       * <p>If this is not present, it is not known whether the credential is a discoverable
       * credential or a server-side credential.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2020/WD-webauthn-2-20200730/#dom-credentialpropertiesoutput-rk">§10.4.
       *     Credential Properties Extension (credProps)</a>
       * @see <a
       *     href="https://www.w3.org/TR/2020/WD-webauthn-2-20200730/#client-side-discoverable-credential">Client-side
       *     discoverable Credential</a>
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
       *     Credential</a>
       */
      public Optional<Boolean> getRk() {
        return Optional.ofNullable(rk);
      }
    }
  }

  /**
   * Definitions for the Large blob storage extension (<code>largeBlob</code>).
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
   *     Large blob storage extension (largeBlob)</a>
   */
  public static class LargeBlob {
    public static final String EXTENSION_ID = "largeBlob";

    /**
     * Extension inputs for the Large blob storage extension (<code>largeBlob</code>) in
     * registration ceremonies.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
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
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
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
         * {@link AuthenticatorSelectionCriteria#isRequireResidentKey()} set to <code>true</code> in
         * {@link StartRegistrationOptions#getAuthenticatorSelection()}.
         *
         * @see <a
         *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
         *     Large blob storage extension (largeBlob)</a>
         */
        public static final LargeBlobSupport REQUIRED = new LargeBlobSupport("required");

        /**
         * If the authenticator used for registration supports the <code>largeBlob</code> extension,
         * it will be enabled for the created credential. If not supported, the credential will be
         * created without large blob support.
         *
         * <p>Note: CTAP authenticators only support <code>largeBlob</code> in combination with
         * {@link AuthenticatorSelectionCriteria#isRequireResidentKey()} set to <code>true</code> in
         * {@link StartRegistrationOptions#getAuthenticatorSelection()}.
         *
         * @see <a
         *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
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
     * @see <a
     *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
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
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargeblobinputs-read">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      @JsonProperty private final Boolean read;

      /**
       * An opaque byte string that the Relying Party wishes to store with the existing credential.
       *
       * @see #write(ByteArray)
       * @see <a
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargeblobinputs-write">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      @JsonProperty private final ByteArray write;

      private LargeBlobAuthenticationInput(final Boolean read, final ByteArray write) {
        if (read != null && read && write != null) {
          throw new IllegalArgumentException(
              "Parameters \"read\" and \"write\" of largeBlob extension must not both be present.");
        }

        this.read = read != null && read ? true : null;
        this.write = write;
      }

      /**
       * Configure the Large blob storage extension (<code>largeBlob</code>) to fetch the
       * previously-written blob associated with the asserted credential.
       *
       * <p>Mutually exclusive with {@link #write(ByteArray)}.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargeblobinputs-read">§10.5.
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
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargeblobinputs-write">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public static LargeBlobAuthenticationInput write(@NonNull final ByteArray write) {
        return new LargeBlobAuthenticationInput(false, write);
      }
    }

    /**
     * Extension outputs for the Large blob storage extension (<code>largeBlob</code>) in
     * registration ceremonies.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    @Value
    public static class LargeBlobRegistrationOutput {
      /**
       * <code>true</code> if, and only if, the created credential supports storing large blobs.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargebloboutputs-supported">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       * @see LargeBlobRegistrationInput#getSupport()
       */
      @JsonProperty private final boolean supported;

      @JsonCreator
      LargeBlobRegistrationOutput(@JsonProperty("supported") boolean supported) {
        this.supported = supported;
      }
    }

    /**
     * Extension outputs for the Large blob storage extension (<code>largeBlob</code>) in
     * authentication ceremonies.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    @Value
    public static class LargeBlobAuthenticationOutput {
      @JsonProperty private final ByteArray blob;
      @JsonProperty private final Boolean written;

      @JsonCreator
      LargeBlobAuthenticationOutput(
          @JsonProperty("blob") ByteArray blob, @JsonProperty("written") Boolean written) {
        this.blob = blob;
        this.written = written;
      }

      /**
       * The opaque byte string that was associated with the credential identified by {@link
       * PublicKeyCredential#getId()}. Only valid if {@link LargeBlobAuthenticationInput#getRead()}
       * was <code>true</code>.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargebloboutputs-blob">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public Optional<ByteArray> getBlob() {
        return Optional.ofNullable(blob);
      }

      /**
       * A boolean that indicates that the contents of {@link
       * LargeBlobAuthenticationInput#write(ByteArray)} were successfully stored on the
       * authenticator, associated with the specified credential.
       *
       * @return Empty if {@link LargeBlobAuthenticationInput#getWrite()} was not present. Otherwise
       *     <code>true</code> if and only if the value of {@link
       *     LargeBlobAuthenticationInput#getWrite()} was successfully stored by the authenticator.
       * @see <a
       *     href="https://www.w3.org/TR/2021/PR-webauthn-2-20210225/#dom-authenticationextensionslargebloboutputs-written">§10.5.
       *     Large blob storage extension (largeBlob)</a>
       */
      public Optional<Boolean> getWritten() {
        return Optional.ofNullable(written);
      }
    }
  }

  public static class Uvm {
    public static final String EXTENSION_ID = "uvm";

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

      /**
       * Enum-like collection of known <code>USER_VERIFY</code> values.
       *
       * <p>Constants in this class behave like enum constants. Use {@link #of(int)} to parse raw
       * <code>int</code> values.
       *
       * @see #of(int)
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
       *     Registry of Predefined Values §3.1 User Verification Methods</a>
       */
      @EqualsAndHashCode
      public static class UserVerificationMethod {

        /**
         * This flag MUST be set if the authenticator is able to confirm user presence in any
         * fashion. If this flag and no other is set for user verification, the guarantee is only
         * that the authenticator cannot be operated without some human intervention, not
         * necessarily that the sensing of "presence" provides any level of user verification (e.g.
         * a device that requires a button press to activate).
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_PRESENCE =
            new UserVerificationMethod(0x00000001, "PRESENCE");

        /**
         * This flag MUST be set if the authenticator uses any type of measurement of a fingerprint
         * for user verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_FINGERPRINT =
            new UserVerificationMethod(0x00000002, "FINGERPRINT");

        /**
         * This flag MUST be set if the authenticator uses a local-only passcode (i.e. a passcode
         * not known by the server) for user verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_PASSCODE =
            new UserVerificationMethod(0x00000004, "PASSCODE");

        /**
         * This flag MUST be set if the authenticator uses a voiceprint (also known as speaker
         * recognition) for user verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_VOICEPRINT =
            new UserVerificationMethod(0x00000008, "VOICEPRINT");

        /**
         * This flag MUST be set if the authenticator uses any manner of face recognition to verify
         * the user.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_FACEPRINT =
            new UserVerificationMethod(0x00000010, "FACEPRINT");

        /**
         * This flag MUST be set if the authenticator uses any form of location sensor or
         * measurement for user verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_LOCATION =
            new UserVerificationMethod(0x00000020, "LOCATION");

        /**
         * This flag MUST be set if the authenticator uses any form of eye biometrics for user
         * verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_EYEPRINT =
            new UserVerificationMethod(0x00000040, "EYEPRINT");

        /**
         * This flag MUST be set if the authenticator uses a drawn pattern for user verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_PATTERN =
            new UserVerificationMethod(0x00000080, "PATTERN");

        /**
         * This flag MUST be set if the authenticator uses any measurement of a full hand (including
         * palm-print, hand geometry or vein geometry) for user verification.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_HANDPRINT =
            new UserVerificationMethod(0x00000100, "HANDPRINT");

        /**
         * This flag MUST be set if the authenticator will respond without any user interaction
         * (e.g. Silent Authenticator).
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_NONE =
            new UserVerificationMethod(0x00000200, "NONE");

        /**
         * If an authenticator sets multiple flags for user verification types, it MAY also set this
         * flag to indicate that all verification methods will be enforced (e.g. faceprint AND
         * voiceprint). If flags for multiple user verification methods are set and this flag is not
         * set, verification with only one is necessary (e.g. fingerprint OR passcode).
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public static final UserVerificationMethod USER_VERIFY_ALL =
            new UserVerificationMethod(0x00000400, "ALL");

        @JsonValue public final int value;

        @EqualsAndHashCode.Exclude private final transient String name;

        private UserVerificationMethod(int value, String name) {
          this.value = value;
          this.name = name;
        }

        /**
         * @return An array containing all predefined values of {@link UserVerificationMethod} known
         *     by this implementation.
         */
        public static UserVerificationMethod[] values() {
          return new UserVerificationMethod[] {
            USER_VERIFY_PRESENCE,
            USER_VERIFY_FINGERPRINT,
            USER_VERIFY_PASSCODE,
            USER_VERIFY_VOICEPRINT,
            USER_VERIFY_FACEPRINT,
            USER_VERIFY_LOCATION,
            USER_VERIFY_EYEPRINT,
            USER_VERIFY_PATTERN,
            USER_VERIFY_HANDPRINT,
            USER_VERIFY_NONE,
            USER_VERIFY_ALL
          };
        }

        /**
         * @return If <code>value</code> is the same as that of any of the constants in {@link
         *     UserVerificationMethod}, returns that constant instance. Otherwise returns a new
         *     instance containing <code>value</code>.
         */
        @JsonCreator
        public static UserVerificationMethod of(int value) {
          return Stream.of(values())
              .filter(v -> v.value == value)
              .findAny()
              .orElseGet(() -> new UserVerificationMethod(value, null));
        }

        @Override
        public String toString() {
          if (name == null) {
            return String.format("%s(%04x)", UserVerificationMethod.class.getSimpleName(), value);
          } else {
            return name;
          }
        }
      }

      /**
       * Enum-like collection of known <code>KEY_PROTECTION</code> values.
       *
       * <p>Constants in this class behave like enum constants. Use {@link #of(short)} to parse raw
       * <code>int</code> values.
       *
       * @see #of(short)
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
       *     Registry of Predefined Values §3.2 Key Protection Types</a>
       */
      @EqualsAndHashCode
      public static class KeyProtectionType {

        /**
         * This flag must be set if the authenticator uses software-based key management. Mutually
         * exclusive with {@link #KEY_PROTECTION_HARDWARE}, {@link #KEY_PROTECTION_TEE}, {@link
         * #KEY_PROTECTION_SECURE_ELEMENT}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        public static final KeyProtectionType KEY_PROTECTION_SOFTWARE =
            new KeyProtectionType((short) 0x0001, "SOFTWARE");

        /**
         * This flag should be set if the authenticator uses hardware-based key management. Mutually
         * exclusive with {@link #KEY_PROTECTION_SOFTWARE}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        public static final KeyProtectionType KEY_PROTECTION_HARDWARE =
            new KeyProtectionType((short) 0x0002, "HARDWARE");

        /**
         * This flag should be set if the authenticator uses the Trusted Execution Environment for
         * key management. In authenticator metadata, this flag should be set in conjunction with
         * {@link #KEY_PROTECTION_HARDWARE}. Mutually exclusive with {@link
         * #KEY_PROTECTION_SOFTWARE}, {@link #KEY_PROTECTION_SECURE_ELEMENT}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        public static final KeyProtectionType KEY_PROTECTION_TEE =
            new KeyProtectionType((short) 0x0004, "TEE");

        /**
         * This flag should be set if the authenticator uses a Secure Element for key management. In
         * authenticator metadata, this flag should be set in conjunction with {@link
         * #KEY_PROTECTION_HARDWARE}. Mutually exclusive with {@link #KEY_PROTECTION_TEE}, {@link
         * #KEY_PROTECTION_SOFTWARE}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        public static final KeyProtectionType KEY_PROTECTION_SECURE_ELEMENT =
            new KeyProtectionType((short) 0x0008, "SECURE_ELEMENT");

        /**
         * This flag must be set if the authenticator does not store (wrapped) UAuth keys at the
         * client, but relies on a server-provided key handle. This flag must be set in conjunction
         * with one of the other KEY_PROTECTION flags to indicate how the local key handle wrapping
         * key and operations are protected. Servers may unset this flag in authenticator policy if
         * they are not prepared to store and return key handles, for example, if they have a
         * requirement to respond indistinguishably to authentication attempts against userIDs that
         * do and do not exist. Refer to [UAFProtocol] for more details.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html">FIDO
         *     UAF Protocol Specification [UAFProtocol]</a>
         */
        public static final KeyProtectionType KEY_PROTECTION_REMOTE_HANDLE =
            new KeyProtectionType((short) 0x0010, "REMOTE_HANDLE");

        @JsonValue public final short value;

        @EqualsAndHashCode.Exclude private final transient String name;

        private KeyProtectionType(short value, String name) {
          this.value = value;
          this.name = name;
        }

        /**
         * @return An array containing all predefined values of {@link KeyProtectionType} known by
         *     this implementation.
         */
        public static KeyProtectionType[] values() {
          return new KeyProtectionType[] {
            KEY_PROTECTION_SOFTWARE,
            KEY_PROTECTION_HARDWARE,
            KEY_PROTECTION_TEE,
            KEY_PROTECTION_SECURE_ELEMENT,
            KEY_PROTECTION_REMOTE_HANDLE
          };
        }

        /**
         * @return If <code>value</code> is the same as that of any of the constants in {@link
         *     KeyProtectionType}, returns that constant instance. Otherwise returns a new instance
         *     containing <code>value</code>.
         */
        @JsonCreator
        public static KeyProtectionType of(short value) {
          return Stream.of(values())
              .filter(v -> v.value == value)
              .findAny()
              .orElseGet(() -> new KeyProtectionType(value, null));
        }

        @Override
        public String toString() {
          if (name == null) {
            return String.format("%s(%04x)", KeyProtectionType.class.getSimpleName(), value);
          } else {
            return name;
          }
        }
      }

      /**
       * Enum-like collection of known <code>MATCHER_PROTECTION</code> values.
       *
       * <p>Constants in this class behave like enum constants. Use {@link #of(short)} to parse raw
       * <code>int</code> values.
       *
       * @see #of(short)
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
       *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
       */
      @EqualsAndHashCode
      public static class MatcherProtectionType {

        /**
         * This flag must be set if the authenticator's matcher is running in software. Mutually
         * exclusive with {@link #MATCHER_PROTECTION_TEE}, {@link #MATCHER_PROTECTION_ON_CHIP}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
         *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
         */
        public static final MatcherProtectionType MATCHER_PROTECTION_SOFTWARE =
            new MatcherProtectionType((short) 0x0001, "SOFTWARE");

        /**
         * This flag should be set if the authenticator's matcher is running inside the Trusted
         * Execution Environment. Mutually exclusive with {@link #MATCHER_PROTECTION_SOFTWARE},
         * {@link #MATCHER_PROTECTION_ON_CHIP}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
         *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
         */
        public static final MatcherProtectionType MATCHER_PROTECTION_TEE =
            new MatcherProtectionType((short) 0x0002, "TEE");

        /**
         * This flag should be set if the authenticator's matcher is running on the chip. Mutually
         * exclusive with {@link #MATCHER_PROTECTION_TEE}, {@link #MATCHER_PROTECTION_SOFTWARE}.
         *
         * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce
         * them.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
         *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
         */
        public static final MatcherProtectionType MATCHER_PROTECTION_ON_CHIP =
            new MatcherProtectionType((short) 0x0004, "ON_CHIP");

        @JsonValue public final short value;

        @EqualsAndHashCode.Exclude private final transient String name;

        private MatcherProtectionType(short value, String name) {
          this.value = value;
          this.name = name;
        }

        /**
         * @return An array containing all predefined values of {@link MatcherProtectionType} known
         *     by this implementation.
         */
        public static MatcherProtectionType[] values() {
          return new MatcherProtectionType[] {
            MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP
          };
        }

        /**
         * @return If <code>value</code> is the same as that of any of the constants in {@link
         *     MatcherProtectionType}, returns that constant instance. Otherwise returns a new
         *     instance containing <code>value</code>.
         */
        @JsonCreator
        public static MatcherProtectionType of(short value) {
          return Stream.of(values())
              .filter(v -> v.value == value)
              .findAny()
              .orElseGet(() -> new MatcherProtectionType(value, null));
        }

        @Override
        public String toString() {
          if (name == null) {
            return String.format("%s(%04x)", MatcherProtectionType.class.getSimpleName(), value);
          } else {
            return name;
          }
        }
      }
    }

    static Optional<List<UvmEntry>> parseAuthenticatorExtensionOutput(CBORObject cbor) {
      if (validateAuthenticatorExtensionOutput(cbor)) {
        return Optional.of(
            cbor.get(EXTENSION_ID).getValues().stream()
                .map(
                    uvmEntry ->
                        new UvmEntry(
                            UvmEntry.UserVerificationMethod.of(uvmEntry.get(0).AsInt32Value()),
                            UvmEntry.KeyProtectionType.of(uvmEntry.get(1).AsInt16()),
                            UvmEntry.MatcherProtectionType.of(uvmEntry.get(2).AsInt16())))
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
          if (!i.isIntegral()) {
            log.debug("Invalid type for uvmEntry element: expected integer, was: {}", i.getType());
            return false;
          }
        }
      }

      return true;
    }
  }
}
