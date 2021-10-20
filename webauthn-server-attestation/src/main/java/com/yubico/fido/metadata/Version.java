package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Value;

/**
 * Represents a generic version with major and minor fields.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface">FIDO
 *     UAF Protocol Specification §3.1.1 Version Interface</a>
 */
@Value
public class Version {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface">FIDO
   *     UAF Protocol Specification §3.1.1 Version Interface</a>
   */
  int major;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface">FIDO
   *     UAF Protocol Specification §3.1.1 Version Interface</a>
   */
  int minor;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface">FIDO
   *     UAF Protocol Specification §3.1.1 Version Interface</a>
   */
  @JsonCreator
  public Version(@JsonProperty("major") int major, @JsonProperty("minor") int minor) {
    this.major = major;
    this.minor = minor;
  }
}
