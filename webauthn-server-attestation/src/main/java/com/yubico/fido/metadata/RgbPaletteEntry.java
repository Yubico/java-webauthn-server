package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Value;

/**
 * The rgbPaletteEntry is an RGB three-sample tuple palette entry.
 *
 * <p><a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#rgbpaletteentry-dictionary">FIDO
 * Metadata Statement §3.7. rgbPaletteEntry dictionary</a>
 */
@Value
public class RgbPaletteEntry {

  int r;
  int g;
  int b;

  @JsonCreator
  public RgbPaletteEntry(
      @JsonProperty("r") int r, @JsonProperty("g") int g, @JsonProperty("b") int b) {
    this.r = r;
    this.g = g;
    this.b = b;
  }
}
