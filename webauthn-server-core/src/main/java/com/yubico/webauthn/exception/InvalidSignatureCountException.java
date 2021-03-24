package com.yubico.webauthn.exception;

import com.yubico.webauthn.data.ByteArray;
import lombok.EqualsAndHashCode;
import lombok.Value;

@Value
@EqualsAndHashCode(callSuper = true)
public class InvalidSignatureCountException extends AssertionFailedException {

  private final ByteArray credentialId;
  private final long expectedMinimum;
  private final long received;

  public InvalidSignatureCountException(
      ByteArray credentialId, long expectedMinimum, long received) {
    super(
        String.format(
            "Signature counter must increase. Expected minimum: %s, received value: %s",
            expectedMinimum, received));
    this.credentialId = credentialId;
    this.expectedMinimum = expectedMinimum;
    this.received = received;
  }
}
