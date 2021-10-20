package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * Contains an {@link AuthenticatorStatus} and additional data associated with it, if any.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
 *     Metadata Service §3.1.3. StatusReport dictionary</a>
 */
@Value
@Builder
@Jacksonized
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class StatusReport {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  @NonNull AuthenticatorStatus status;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  LocalDate effectiveDate;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  Long authenticatorVersion;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  @JsonDeserialize(converter = CertFromBase64Converter.class)
  @JsonSerialize(converter = CertToBase64Converter.class)
  X509Certificate certificate;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  @JsonProperty("url")
  @Getter(AccessLevel.NONE)
  String url;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  String certificationDescriptor;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  String certificateNumber;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  String certificationPolicyVersion;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  String certificationRequirementsVersion;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  public Optional<LocalDate> getEffectiveDate() {
    return Optional.ofNullable(effectiveDate);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  public Optional<Long> getAuthenticatorVersion() {
    return Optional.ofNullable(authenticatorVersion);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  @JsonIgnore
  public Optional<X509Certificate> getCertificate() {
    return Optional.ofNullable(this.certificate);
  }

  /**
   * Attempt to parse the {@link #getUrlAsString() url} property, if any, as a {@link URL}.
   *
   * @return A present value if and only if {@link #getUrlAsString()} is present and a valid URL.
   */
  public Optional<URL> getUrl() {
    try {
      return Optional.of(new URL(url));
    } catch (MalformedURLException e) {
      return Optional.empty();
    }
  }

  /**
   * Get the raw <code>url</code> property of this {@link StatusReport} object. This may or may not
   * be a valid URL.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  @JsonIgnore
  public Optional<String> getUrlAsString() {
    return Optional.ofNullable(this.url);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  public Optional<String> getCertificationDescriptor() {
    return Optional.ofNullable(this.certificationDescriptor);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  public Optional<String> getCertificateNumber() {
    return Optional.ofNullable(this.certificateNumber);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  public Optional<String> getCertificationPolicyVersion() {
    return Optional.ofNullable(this.certificationPolicyVersion);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary">FIDO
   *     Metadata Service §3.1.3. StatusReport dictionary</a>
   */
  public Optional<String> getCertificationRequirementsVersion() {
    return Optional.ofNullable(this.certificationRequirementsVersion);
  }
}
