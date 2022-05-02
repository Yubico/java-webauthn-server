package com.yubico.fido.metadata;

import com.yubico.webauthn.extension.uvm.UserVerificationMethod;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * A descriptor for a specific <i>base user verification method</i> as implemented by the
 * authenticator.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO
 *     Metadata Statement §3.5. VerificationMethodDescriptor dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class VerificationMethodDescriptor {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO
   *     Metadata Statement §3.5. VerificationMethodDescriptor dictionary</a>
   */
  UserVerificationMethod userVerificationMethod;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO
   *     Metadata Statement §3.5. VerificationMethodDescriptor dictionary</a>
   */
  CodeAccuracyDescriptor caDesc;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO
   *     Metadata Statement §3.5. VerificationMethodDescriptor dictionary</a>
   */
  BiometricAccuracyDescriptor baDesc;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO
   *     Metadata Statement §3.5. VerificationMethodDescriptor dictionary</a>
   */
  PatternAccuracyDescriptor paDesc;
}
