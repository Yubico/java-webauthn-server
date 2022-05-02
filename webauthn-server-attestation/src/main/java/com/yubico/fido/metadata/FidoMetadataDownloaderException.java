package com.yubico.fido.metadata;

import lombok.NonNull;
import lombok.Value;

@Value
public class FidoMetadataDownloaderException extends Exception {

  public enum Reason {
    BAD_SIGNATURE("Bad JWT signature.");

    private final String message;

    Reason(String message) {
      this.message = message;
    }
  }

  @NonNull
  /** The reason why this exception was thrown. */
  private final Reason reason;

  /** A {@link Throwable} that caused this exception. May be null. */
  private final Throwable cause;

  FidoMetadataDownloaderException(Reason reason, Throwable cause) {
    this.reason = reason;
    this.cause = cause;
  }

  FidoMetadataDownloaderException(Reason reason) {
    this(reason, null);
  }

  @Override
  public String getMessage() {
    return reason.message;
  }
}
