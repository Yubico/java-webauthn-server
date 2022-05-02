package com.yubico.fido.metadata;

import java.util.List;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the
 * PNG [<a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biblio-png">PNG</a>]
 * spec for IHDR (image header) and PLTE (palette table).
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
 *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class DisplayPNGCharacteristicsDescriptor {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  long width;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  long height;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  short bitDepth;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  short colorType;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  short compression;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  short filter;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  short interlace;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO
   *     Metadata Statement §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
   */
  List<RgbPaletteEntry> plte;
}
