package com.yubico.fido.metadata;

import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

/**
 * A FIDO Metadata Service metadata BLOB was successfully downloaded and validated, but contained an
 * unexpected legal header.
 *
 * <p>This exception contains the offending downloaded metadata BLOB as well as the cached metadata
 * BLOB, if any (see {@link #getCachedBlob()}). This enables applications to gracefully fall back to
 * the cached blob when possible, while notifying maintainers that action is required for the new
 * legal header.
 */
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class UnexpectedLegalHeader extends Exception {

  /** The cached metadata BLOB, if any, which is assumed to have an expected legal header. */
  private final MetadataBLOB cachedBlob;

  /**
   * The newly downloaded metadata BLOB, which has an unexpected legal header.
   *
   * <p>The unexpected legal header can be retrieved via the {@link MetadataBLOB#getPayload()
   * getPayload()}.{@link MetadataBLOBPayload#getLegalHeader() getLegalHeader()} methods.
   *
   * @see MetadataBLOB#getPayload()
   * @see MetadataBLOBPayload#getLegalHeader()
   */
  @Getter @NonNull private final MetadataBLOB downloadedBlob;

  /** The cached metadata BLOB, if any. */
  public Optional<MetadataBLOB> getCachedBlob() {
    return Optional.ofNullable(cachedBlob);
  }
}
