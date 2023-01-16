package com.yubico.fido.metadata;

import lombok.Getter;
import lombok.NonNull;

public class FidoMetadataDownloaderException extends Exception {

  public enum Reason {
    BAD_SIGNATURE("Bad JWT signature.");

    private final String message;

    Reason(String message) {
      this.message = message;
    }
  }

  @NonNull @Getter
  /** The reason why this exception was thrown. */
  private final Reason reason;

  /** A {@link Throwable} that caused this exception. May be null. */
  @Getter private final Throwable cause;

  FidoMetadataDownloaderException(@NonNull Reason reason, Throwable cause) {
    super(cause);
    this.reason = reason;
    this.cause = cause;
  }

  FidoMetadataDownloaderException(@NonNull Reason reason) {
    this(reason, null);
  }

  @Override
  public String getMessage() {
    return reason.message;
  }
}
