package com.yubico.fido.metadata;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * The metadata BLOB is a JSON Web Token (see [<a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-jwt">JWT</a>]
 * and [<a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-jws">JWS</a>]).
 *
 * <p>This type represents the contents of the JWT header.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
 *     Metadata Service §3.1.7. Metadata BLOB</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519: JSON Web Token (JWT)</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class MetadataBLOBHeader {

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-5.1">RFC 7519 §5.1. "typ"
   *     (Type) Header Parameter</a>
   */
  String typ;

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1">RFC 7515 §4.1.1.
   *     "alg" (Algorithm) Header Parameter</a>
   */
  @NonNull String alg;

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5">RFC 7515 §4.1.5.
   *     "x5u" (X.509 URL) Header Parameter</a>
   */
  URL x5u;

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6">RFC 7515 §4.1.6.
   *     "x5c" (X.509 Certificate Chain) Header Parameter</a>
   */
  @JsonDeserialize(contentConverter = CertFromBase64Converter.class)
  @JsonSerialize(contentConverter = CertToBase64Converter.class)
  List<X509Certificate> x5c;

  private MetadataBLOBHeader(String typ, @NonNull String alg, URL x5u, List<X509Certificate> x5c) {
    this.typ = typ;
    this.alg = alg;
    this.x5u = x5u;
    this.x5c = x5c;

    if (typ != null && !typ.equals("JWT")) {
      throw new IllegalArgumentException("Unsupported JWT type: " + typ);
    }
  }

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-5.1">RFC 7519 §5.1. "typ"
   *     (Type) Header Parameter</a>
   */
  public Optional<String> getTyp() {
    return Optional.ofNullable(typ);
  }

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5">RFC 7515 §4.1.5.
   *     "x5u" (X.509 URL) Header Parameter</a>
   */
  public Optional<URL> getX5u() {
    return Optional.ofNullable(x5u);
  }

  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6">RFC 7515 §4.1.6.
   *     "x5c" (X.509 Certificate Chain) Header Parameter</a>
   */
  public Optional<List<X509Certificate>> getX5c() {
    return Optional.ofNullable(x5c);
  }
}
