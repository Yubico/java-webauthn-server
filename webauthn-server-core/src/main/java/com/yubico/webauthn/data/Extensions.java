package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.yubico.webauthn.StartRegistrationOptions;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
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
      private final UserVerificationMethodFlags userVerificationMethod;
      private final KeyProtectionTypeFlags keyProtectionType;
      private final MatcherProtectionTypeFlags matcherProtectionType;

      public UvmEntry(
          @JsonProperty("userVerificationMethod")
              UserVerificationMethodFlags userVerificationMethod,
          @JsonProperty("keyProtectionType") KeyProtectionTypeFlags keyProtectionType,
          @JsonProperty("matcherProtectionType") MatcherProtectionTypeFlags matcherProtectionType) {
        this.userVerificationMethod = userVerificationMethod;
        this.keyProtectionType = keyProtectionType;
        this.matcherProtectionType = matcherProtectionType;
      }

      /**
       * A set of <code>USER_VERIFY</code> flags, represented as a bit field.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
       *     User Verification Method Extension (uvm)</a>
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
       *     Registry of Predefined Values §3.1 User Verification Methods</a>
       */
      @Value
      @AllArgsConstructor(onConstructor = @__({@JsonCreator}))
      public static class UserVerificationMethodFlags {
        /**
         * The <code>USER_VERIFY</code> bit field representing this set of user verification
         * methods.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        @JsonValue private final int value;

        static UserVerificationMethodFlags fromFlags(Iterable<UserVerificationMethod> flags) {
          int value = 0;
          for (UserVerificationMethod flag : flags) {
            value = value | flag.value;
          }
          return new UserVerificationMethodFlags(value);
        }

        /**
         * The set of <code>USER_VERIFY</code> flags present in this bit field.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public Set<UserVerificationMethod> flags() {
          Set<UserVerificationMethod> flags = new HashSet<>();
          for (UserVerificationMethod flag : UserVerificationMethod.values()) {
            if ((flag.value & value) != 0) {
              flags.add(flag);
            }
          }
          return flags;
        }

        /**
         * Check whether this bit field has the given <code>USER_VERIFY</code> flag set.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
         *     Registry of Predefined Values §3.1 User Verification Methods</a>
         */
        public boolean has(UserVerificationMethod flag) {
          return (flag.value & value) != 0;
        }
      }

      /**
       * The set of <code>USER_VERIFY</code> flags that can be present in a {@link
       * UserVerificationMethodFlags} value.
       *
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
       *     Registry of Predefined Values §3.1 User Verification Methods</a>
       */
      public enum UserVerificationMethod {
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
        USER_VERIFY_PRESENCE(0x00000001),
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
        USER_VERIFY_FINGERPRINT(0x00000002),
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
        USER_VERIFY_PASSCODE(0x00000004),
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
        USER_VERIFY_VOICEPRINT(0x00000008),
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
        USER_VERIFY_FACEPRINT(0x00000010),
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
        USER_VERIFY_LOCATION(0x00000020),
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
        USER_VERIFY_EYEPRINT(0x00000040),
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
        USER_VERIFY_PATTERN(0x00000080),
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
        USER_VERIFY_HANDPRINT(0x00000100),
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
        USER_VERIFY_NONE(0x00000200),
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
        USER_VERIFY_ALL(0x00000400);

        private final int value;

        UserVerificationMethod(int value) {
          this.value = value;
        }
      }

      /**
       * A set of <code>KEY_PROTECTION</code> flags, represented as a bit field.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
       *     User Verification Method Extension (uvm)</a>
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
       *     Registry of Predefined Values §3.2 Key Protection Types</a>
       */
      @Value
      @AllArgsConstructor(onConstructor = @__({@JsonCreator}))
      public static class KeyProtectionTypeFlags {
        /**
         * The <code>KEY_PROTECTION</code> bit field representing this set of key protection types.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        @JsonValue private final short value;

        static KeyProtectionTypeFlags fromFlags(Iterable<KeyProtectionType> flags) {
          short value = 0;
          for (KeyProtectionType flag : flags) {
            value = (short) (value | flag.value);
          }
          return new KeyProtectionTypeFlags(value);
        }

        /**
         * The set of <code>KEY_PROTECTION</code> flags present in this bit field.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        public Set<KeyProtectionType> flags() {
          Set<KeyProtectionType> flags = new HashSet<>();
          for (KeyProtectionType flag : KeyProtectionType.values()) {
            if ((flag.value & value) != 0) {
              flags.add(flag);
            }
          }
          return flags;
        }

        /**
         * Check whether this bit field has the given <code>KEY_PROTECTION</code> flag set.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
         *     Registry of Predefined Values §3.2 Key Protection Types</a>
         */
        public boolean has(KeyProtectionType flag) {
          return (flag.value & value) != 0;
        }
      }

      /**
       * The set of <code>KEY_PROTECTION</code> flags that can be present in a {@link
       * KeyProtectionTypeFlags} value.
       *
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
       *     Registry of Predefined Values §3.2 Key Protection Types</a>
       */
      public enum KeyProtectionType {

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
        KEY_PROTECTION_SOFTWARE((short) 0x0001),

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
        KEY_PROTECTION_HARDWARE((short) 0x0002),

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
        KEY_PROTECTION_TEE((short) 0x0004),

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
        KEY_PROTECTION_SECURE_ELEMENT((short) 0x0008),

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
        KEY_PROTECTION_REMOTE_HANDLE((short) 0x0010);

        private final short value;

        KeyProtectionType(short value) {
          this.value = value;
        }
      }

      /**
       * A set of <code>MATCHER_PROTECTION</code> flags, represented as a bit field.
       *
       * @see <a
       *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
       *     User Verification Method Extension (uvm)</a>
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
       *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
       */
      @Value
      @AllArgsConstructor(onConstructor = @__({@JsonCreator}))
      public static class MatcherProtectionTypeFlags {
        /**
         * The <code>MATCHER_PROTECTION</code> bit field representing this set of matcher protection
         * types.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
         *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
         */
        @JsonValue private final short value;

        static MatcherProtectionTypeFlags fromFlags(Iterable<MatcherProtectionType> flags) {
          short value = 0;
          for (MatcherProtectionType flag : flags) {
            value = (short) (value | flag.value);
          }
          return new MatcherProtectionTypeFlags(value);
        }

        /**
         * The set of <code>MATCHER_PROTECTION</code> flags present in this bit field.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
         *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
         */
        public Set<MatcherProtectionType> flags() {
          Set<MatcherProtectionType> flags = new HashSet<>();
          for (MatcherProtectionType flag : MatcherProtectionType.values()) {
            if ((flag.value & value) != 0) {
              flags.add(flag);
            }
          }
          return flags;
        }

        /**
         * Check whether this bit field has the given <code>MATCHER_PROTECTION</code> flag set.
         *
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
         *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
         */
        public boolean has(KeyProtectionType flag) {
          return (flag.value & value) != 0;
        }
      }

      /**
       * The set of <code>MATCHER_PROTECTION</code> flags that can be present in a {@link
       * MatcherProtectionTypeFlags} value.
       *
       * @see <a
       *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
       *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
       */
      public enum MatcherProtectionType {

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
        MATCHER_PROTECTION_SOFTWARE((short) 0x0001),

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
        MATCHER_PROTECTION_TEE((short) 0x0002),

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
        MATCHER_PROTECTION_ON_CHIP((short) 0x0004);

        private final short value;

        MatcherProtectionType(short value) {
          this.value = value;
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
                            new UvmEntry.UserVerificationMethodFlags(
                                uvmEntry.get(0).AsInt32Value()),
                            new UvmEntry.KeyProtectionTypeFlags(uvmEntry.get(1).AsInt16()),
                            new UvmEntry.MatcherProtectionTypeFlags(uvmEntry.get(2).AsInt16())))
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
