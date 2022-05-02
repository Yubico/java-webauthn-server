package com.yubico.fido.metadata

import com.yubico.scalacheck.gen.JavaGenerators.arbitraryUrl
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.AuthenticatorTransport
import com.yubico.webauthn.data.Generators.arbitraryAuthenticatorTransport
import com.yubico.webauthn.data.Generators.arbitraryPublicKeyCredentialParameters
import com.yubico.webauthn.data.Generators.byteArray
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.extension.uvm.KeyProtectionType
import com.yubico.webauthn.extension.uvm.MatcherProtectionType
import com.yubico.webauthn.extension.uvm.UserVerificationMethod
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import java.net.URL
import java.security.cert.X509Certificate
import java.time.LocalDate
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.jdk.CollectionConverters.SeqHasAsJava
import scala.jdk.CollectionConverters.SetHasAsJava

object Generators {

  implicit val arbitraryMetadataBLOBHeader: Arbitrary[MetadataBLOBHeader] =
    Arbitrary(
      for {
        alg <- arbitrary[String]
        typ <- Gen.option(Gen.const("JWT"))
        x5u <- arbitrary[Option[URL]]
        x5c <- Gen.option(
          Gen
            .chooseNum(0, 4)
            .flatMap(n =>
              Gen.listOfN(
                n,
                TestAuthenticator.generateAttestationCertificate()._1,
              )
            )
        )
      } yield MetadataBLOBHeader
        .builder()
        .alg(alg)
        .typ(typ.orNull)
        .x5u(x5u.orNull)
        .x5c(x5c.map(_.asJava).orNull)
        .build()
    )

  implicit val arbitraryMetadataBLOBPayload: Arbitrary[MetadataBLOBPayload] =
    Arbitrary(
      for {
        legalHeader <- arbitrary[Option[String]]
        no <- arbitrary[Int]
        nextUpdate <- arbitrary[LocalDate]
        entries <-
          Gen
            .chooseNum(0, 4)
            .flatMap(n =>
              Gen.containerOfN[Set, MetadataBLOBPayloadEntry](
                n,
                arbitrary[MetadataBLOBPayloadEntry],
              )
            )
      } yield new MetadataBLOBPayload(
        legalHeader.orNull,
        no,
        nextUpdate,
        entries.asJava,
      )
    )

  implicit val arbitraryMetadataBLOBPayloadEntry
      : Arbitrary[MetadataBLOBPayloadEntry] = Arbitrary(
    for {
      aaid <- arbitrary[Option[AAID]]
      aaguid <- arbitrary[Option[AAGUID]]
      attestationCertificateKeyIdentifiers <- Gen.option(
        Gen.containerOf[Set, String](byteArray(32, 32).map(_.getHex))
      )
      metadataStatement <- arbitrary[Option[MetadataStatement]]
      biometricStatusReports <- arbitrary[Option[List[BiometricStatusReport]]]
      statusReports <- arbitrary[List[StatusReport]]
      timeOfLastStatusChange <- arbitrary[LocalDate]
      rogueListURL <- arbitrary[Option[URL]]
      rogueListHash <- Gen.option(byteArray(1, 512))
    } yield MetadataBLOBPayloadEntry
      .builder()
      .aaid(aaid.orNull)
      .aaguid(aaguid.orNull)
      .attestationCertificateKeyIdentifiers(
        attestationCertificateKeyIdentifiers.map(_.asJava).orNull
      )
      .metadataStatement(metadataStatement.orNull)
      .biometricStatusReports(biometricStatusReports.map(_.asJava).orNull)
      .statusReports(statusReports.asJava)
      .timeOfLastStatusChange(timeOfLastStatusChange)
      .rogueListURL(rogueListURL.orNull)
      .rogueListHash(rogueListHash.orNull)
      .build()
  )

  implicit val arbitraryAaid: Arbitrary[AAID] = Arbitrary(for {
    prefix <- byteArray(2, 2)
    suffix <- byteArray(2, 2)
  } yield new AAID(s"${prefix.getHex}#${suffix.getHex}"))

  implicit val arbitraryAaguid: Arbitrary[AAGUID] = Arbitrary(
    byteArray(16, 16).map(new AAGUID(_))
  )

  implicit val arbitraryBiometricStatusReport
      : Arbitrary[BiometricStatusReport] = Arbitrary(
    for {
      certLevel <- arbitrary[Int]
      modality <- arbitrary[UserVerificationMethod]
      effectiveDate <- arbitrary[Option[LocalDate]]
      certificationDescriptor <- arbitrary[Option[String]]
      certificateNumber <- arbitrary[Option[String]]
      certificationPolicyVersion <- arbitrary[Option[String]]
      certificationRequirementsVersion <- arbitrary[Option[String]]
    } yield BiometricStatusReport
      .builder()
      .certLevel(certLevel)
      .modality(modality)
      .effectiveDate(effectiveDate.orNull)
      .certificationDescriptor(certificationDescriptor.orNull)
      .certificateNumber(certificateNumber.orNull)
      .certificationPolicyVersion(certificationPolicyVersion.orNull)
      .certificationRequirementsVersion(certificationRequirementsVersion.orNull)
      .build()
  )

  implicit val arbitraryMetadataStatement: Arbitrary[MetadataStatement] =
    Arbitrary(
      for {
        legalHeader <- arbitrary[Option[String]]
        aaid <- arbitrary[Option[AAID]]
        aaguid <- arbitrary[Option[AAGUID]]
        attestationCertificateKeyIdentifiers <- arbitrary[Option[Set[String]]]
        description <- arbitrary[Option[String]]
        alternativeDescriptions <- arbitrary[Option[AlternativeDescriptions]]
        authenticatorVersion <- arbitrary[Long]
        protocolFamily <- arbitrary[ProtocolFamily]
        schema <- arbitrary[Int]
        upv <- arbitrary[Set[Version]]
        authenticationAlgorithms <- arbitrary[Set[AuthenticationAlgorithm]]
        publicKeyAlgAndEncodings <-
          arbitrary[Set[PublicKeyRepresentationFormat]]
        attestationTypes <- arbitrary[Set[AuthenticatorAttestationType]]
        userVerificationDetails <-
          arbitrary[Set[Set[VerificationMethodDescriptor]]]
        keyProtection <- arbitrary[Set[KeyProtectionType]]
        isKeyRestricted <- arbitrary[Option[Boolean]]
        isFreshUserVerificationRequired <- arbitrary[Option[Boolean]]
        matcherProtection <- arbitrary[Set[MatcherProtectionType]]
        cryptoStrength <- arbitrary[Option[Int]]
        attachmentHint <- arbitrary[Option[Set[AttachmentHint]]]
        tcDisplay <- arbitrary[Set[TransactionConfirmationDisplayType]]
        tcDisplayContentType <- arbitrary[Option[String]]
        tcDisplayPNGCharacteristics <-
          arbitrary[Option[List[DisplayPNGCharacteristicsDescriptor]]]
        attestationRootCertificates <-
          Gen
            .chooseNum(0, 4)
            .flatMap(n =>
              Gen.containerOfN[Set, X509Certificate](
                n,
                TestAuthenticator.generateAttestationCaCertificate()._1,
              )
            )
        icon <- arbitrary[Option[String]]
        supportedExtensions <- arbitrary[Option[Set[ExtensionDescriptor]]]
        authenticatorGetInfo <- arbitrary[Option[AuthenticatorGetInfo]]
      } yield MetadataStatement
        .builder()
        .legalHeader(legalHeader.orNull)
        .aaid(aaid.orNull)
        .aaguid(aaguid.orNull)
        .attestationCertificateKeyIdentifiers(
          attestationCertificateKeyIdentifiers.map(_.asJava).orNull
        )
        .description(description.orNull)
        .alternativeDescriptions(alternativeDescriptions.orNull)
        .authenticatorVersion(authenticatorVersion)
        .protocolFamily(protocolFamily)
        .schema(schema)
        .upv(upv.asJava)
        .authenticationAlgorithms(authenticationAlgorithms.asJava)
        .publicKeyAlgAndEncodings(publicKeyAlgAndEncodings.asJava)
        .attestationTypes(attestationTypes.asJava)
        .userVerificationDetails(userVerificationDetails.map(_.asJava).asJava)
        .keyProtection(keyProtection.asJava)
        .isKeyRestricted(isKeyRestricted.map(java.lang.Boolean.valueOf).orNull)
        .isFreshUserVerificationRequired(
          isFreshUserVerificationRequired.map(java.lang.Boolean.valueOf).orNull
        )
        .matcherProtection(matcherProtection.asJava)
        .cryptoStrength(cryptoStrength.map(Integer.valueOf).orNull)
        .attachmentHint(attachmentHint.map(_.asJava).orNull)
        .tcDisplay(tcDisplay.asJava)
        .tcDisplayContentType(tcDisplayContentType.orNull)
        .tcDisplayPNGCharacteristics(
          tcDisplayPNGCharacteristics.map(_.asJava).orNull
        )
        .attestationRootCertificates(attestationRootCertificates.asJava)
        .icon(icon.orNull)
        .supportedExtensions(supportedExtensions.map(_.asJava).orNull)
        .authenticatorGetInfo(authenticatorGetInfo.orNull)
        .build()
    )

  implicit val arbitraryAlternativeDescriptions
      : Arbitrary[AlternativeDescriptions] = Arbitrary(for {
    entries: Map[String, String] <- Gen.mapOf(for {
      prefix <- Gen.alphaLowerStr.suchThat(_.length >= 2).map(_.take(2))
      suffix <-
        Gen.option(Gen.alphaUpperStr.suchThat(_.length >= 2).map(_.take(2)))
      text <- arbitrary[String]
    } yield (s"${prefix}${suffix.map(s => s"_${s}").getOrElse("")}", text))
  } yield new AlternativeDescriptions(entries.asJava))

  implicit val arbitraryVersion: Arbitrary[Version] = Arbitrary(for {
    major <- arbitrary[Int]
    minor <- arbitrary[Int]
  } yield new Version(major, minor))

  implicit val arbitraryVerificationMethodDescriptor
      : Arbitrary[VerificationMethodDescriptor] = Arbitrary(
    for {
      userVerificationMethod <- arbitrary[UserVerificationMethod]
      caDesc <- arbitrary[CodeAccuracyDescriptor]
      baDesc <- arbitrary[BiometricAccuracyDescriptor]
      paDesc <- arbitrary[PatternAccuracyDescriptor]
    } yield new VerificationMethodDescriptor(
      userVerificationMethod,
      caDesc,
      baDesc,
      paDesc,
    )
  )

  implicit val arbitraryCodeAccuracyDescriptor
      : Arbitrary[CodeAccuracyDescriptor] = Arbitrary(
    for {
      base <- arbitrary[Int]
      minLength <- arbitrary[Int]
      maxRetries <- arbitrary[Option[Int]]
      blockSlowdown <- arbitrary[Option[Int]]
    } yield CodeAccuracyDescriptor
      .builder()
      .base(base)
      .minLength(minLength)
      .maxRetries(maxRetries.map(Integer.valueOf).orNull)
      .blockSlowdown(blockSlowdown.map(Integer.valueOf).orNull)
      .build()
  )

  implicit val arbitraryBiometricAccuracyDescriptor
      : Arbitrary[BiometricAccuracyDescriptor] = Arbitrary(
    for {
      selfAttestedFRR <- arbitrary[Option[Double]]
      selfAttestedFAR <- arbitrary[Option[Double]]
      maxTemplates <- arbitrary[Option[Int]]
      maxRetries <- arbitrary[Option[Int]]
      blockSlowdown <- arbitrary[Option[Int]]
    } yield new BiometricAccuracyDescriptor(
      selfAttestedFRR.map(Double.box).orNull,
      selfAttestedFAR.map(Double.box).orNull,
      maxTemplates.map(Integer.valueOf).orNull,
      maxRetries.map(Integer.valueOf).orNull,
      blockSlowdown.map(Integer.valueOf).orNull,
    )
  )

  implicit val arbitraryPatternAccuracyDescriptor
      : Arbitrary[PatternAccuracyDescriptor] = Arbitrary(
    for {
      minComplexity <- arbitrary[Long]
      maxRetries <- arbitrary[Option[Int]]
      blockSlowdown <- arbitrary[Option[Int]]
    } yield PatternAccuracyDescriptor
      .builder()
      .minComplexity(minComplexity)
      .maxRetries(maxRetries.map(Integer.valueOf).orNull)
      .blockSlowdown(blockSlowdown.map(Integer.valueOf).orNull)
      .build()
  )

  implicit val arbitraryDisplayPNGCharacteristicsDescriptor
      : Arbitrary[DisplayPNGCharacteristicsDescriptor] = Arbitrary(
    for {
      width <- arbitrary[Long]
      height <- arbitrary[Long]
      bitDepth <- arbitrary[Short]
      colorType <- arbitrary[Short]
      compression <- arbitrary[Short]
      filter <- arbitrary[Short]
      interlace <- arbitrary[Short]
      plte <- arbitrary[Option[List[RgbPaletteEntry]]]
    } yield DisplayPNGCharacteristicsDescriptor
      .builder()
      .width(width)
      .height(height)
      .bitDepth(bitDepth)
      .colorType(colorType)
      .compression(compression)
      .filter(filter)
      .interlace(interlace)
      .plte(plte.map(_.asJava).orNull)
      .build()
  )

  implicit val arbitraryRgbPaletteEntry: Arbitrary[RgbPaletteEntry] = Arbitrary(
    for {
      r <- arbitrary[Int]
      g <- arbitrary[Int]
      b <- arbitrary[Int]
    } yield new RgbPaletteEntry(r, g, b)
  )

  implicit val arbitraryExtensionDescriptor: Arbitrary[ExtensionDescriptor] =
    Arbitrary(
      for {
        id <- arbitrary[String]
        tag <- arbitrary[Option[Int]]
        data <- arbitrary[Option[String]]
        failIfUnknown <- arbitrary[Boolean]
      } yield ExtensionDescriptor
        .builder()
        .id(id)
        .tag(tag.map(Integer.valueOf).orNull)
        .data(data.orNull)
        .failIfUnknown(failIfUnknown)
        .build()
    )

  implicit val arbitraryAuthenticatorGetInfo: Arbitrary[AuthenticatorGetInfo] =
    Arbitrary(
      for {
        versions <- arbitrary[Set[CtapVersion]]
        extensions <- arbitrary[Option[Set[String]]]
        aaguid <- arbitrary[Option[AAGUID]]
        options <- arbitrary[Option[SupportedCtapOptions]]
        maxMsgSize <- arbitrary[Option[Int]]
        pinUvAuthProtocols <-
          arbitrary[Option[Set[CtapPinUvAuthProtocolVersion]]]
        maxCredentialCountInList <- arbitrary[Option[Int]]
        maxCredentialIdLength <- arbitrary[Option[Int]]
        transports <- arbitrary[Option[Set[AuthenticatorTransport]]]
        algorithms <- arbitrary[Option[List[PublicKeyCredentialParameters]]]
        maxSerializedLargeBlobArray <- arbitrary[Option[Int]]
        forcePINChange <- arbitrary[Option[Boolean]]
        minPINLength <- arbitrary[Option[Int]]
        firmwareVersion <- arbitrary[Option[Int]]
        maxCredBlobLength <- arbitrary[Option[Int]]
        maxRPIDsForSetMinPINLength <- arbitrary[Option[Int]]
        preferredPlatformUvAttempts <- arbitrary[Option[Int]]
        uvModality <- arbitrary[Option[Set[UserVerificationMethod]]]
        certifications <- arbitrary[Option[Map[CtapCertificationId, Int]]]
        remainingDiscoverableCredentials <- arbitrary[Option[Int]]
        vendorPrototypeConfigCommands <- arbitrary[Option[Set[Int]]]
      } yield AuthenticatorGetInfo
        .builder()
        .versions(versions.asJava)
        .extensions(extensions.map(_.asJava).orNull)
        .aaguid(aaguid.orNull)
        .options(options.orNull)
        .maxMsgSize(maxMsgSize.map(Integer.valueOf).orNull)
        .pinUvAuthProtocols(pinUvAuthProtocols.map(_.asJava).orNull)
        .maxCredentialCountInList(
          maxCredentialCountInList.map(Integer.valueOf).orNull
        )
        .maxCredentialIdLength(
          maxCredentialIdLength.map(Integer.valueOf).orNull
        )
        .transports(transports.map(_.asJava).orNull)
        .algorithms(algorithms.map(_.asJava).orNull)
        .maxSerializedLargeBlobArray(
          maxSerializedLargeBlobArray.map(Integer.valueOf).orNull
        )
        .forcePINChange(forcePINChange.map(java.lang.Boolean.valueOf).orNull)
        .minPINLength(minPINLength.map(Integer.valueOf).orNull)
        .firmwareVersion(firmwareVersion.map(Integer.valueOf).orNull)
        .maxCredBlobLength(maxCredBlobLength.map(Integer.valueOf).orNull)
        .maxRPIDsForSetMinPINLength(
          maxRPIDsForSetMinPINLength.map(Integer.valueOf).orNull
        )
        .preferredPlatformUvAttempts(
          preferredPlatformUvAttempts.map(Integer.valueOf).orNull
        )
        .uvModality(uvModality.map(_.asJava).orNull)
        .certifications(
          certifications
            .map(_.map({ case (k, v) => (k, Integer.valueOf(v)) }).asJava)
            .orNull
        )
        .remainingDiscoverableCredentials(
          remainingDiscoverableCredentials.map(Integer.valueOf).orNull
        )
        .vendorPrototypeConfigCommands(
          vendorPrototypeConfigCommands
            .map(_.map(Integer.valueOf).asJava)
            .orNull
        )
        .build()
    )

  implicit val arbitrarySupportedCtapOptions: Arbitrary[SupportedCtapOptions] =
    Arbitrary(
      for {
        plat <- arbitrary[Boolean]
        rk <- arbitrary[Boolean]
        clientPin <- arbitrary[Boolean]
        up <- arbitrary[Boolean]
        uv <- arbitrary[Boolean]
        pinUvAuthToken <- arbitrary[Boolean]
        noMcGaPermissionsWithClientPin <- arbitrary[Boolean]
        largeBlobs <- arbitrary[Boolean]
        ep <- arbitrary[Boolean]
        bioEnroll <- arbitrary[Boolean]
        userVerificationMgmtPreview <- arbitrary[Boolean]
        uvBioEnroll <- arbitrary[Boolean]
        authnrCfg <- arbitrary[Boolean]
        uvAcfg <- arbitrary[Boolean]
        credMgmt <- arbitrary[Boolean]
        credentialMgmtPreview <- arbitrary[Boolean]
        setMinPINLength <- arbitrary[Boolean]
        makeCredUvNotRqd <- arbitrary[Boolean]
        alwaysUv <- arbitrary[Boolean]
      } yield SupportedCtapOptions
        .builder()
        .plat(plat)
        .rk(rk)
        .clientPin(clientPin)
        .up(up)
        .uv(uv)
        .pinUvAuthToken(pinUvAuthToken)
        .noMcGaPermissionsWithClientPin(noMcGaPermissionsWithClientPin)
        .largeBlobs(largeBlobs)
        .ep(ep)
        .bioEnroll(bioEnroll)
        .userVerificationMgmtPreview(userVerificationMgmtPreview)
        .uvBioEnroll(uvBioEnroll)
        .authnrCfg(authnrCfg)
        .uvAcfg(uvAcfg)
        .credMgmt(credMgmt)
        .credentialMgmtPreview(credentialMgmtPreview)
        .setMinPINLength(setMinPINLength)
        .makeCredUvNotRqd(makeCredUvNotRqd)
        .alwaysUv(alwaysUv)
        .build()
    )

  implicit val arbitraryStatusReport: Arbitrary[StatusReport] = Arbitrary(
    for {
      status <- arbitrary[AuthenticatorStatus]
      effectiveDate <- arbitrary[Option[LocalDate]]
      authenticatorVersion <- arbitrary[Option[Long]]
      certificate <- Gen.option(
        Gen.delay(
          Gen
            .const(TestAuthenticator.generateAttestationCertificate())
            .map(_._1)
        )
      )
      url <- arbitrary[Option[String]]
      certificationDescriptor <- arbitrary[Option[String]]
      certificateNumber <- arbitrary[Option[String]]
      certificationPolicyVersion <- arbitrary[Option[String]]
      certificationRequirementsVersion <- arbitrary[Option[String]]
    } yield StatusReport
      .builder()
      .status(status)
      .effectiveDate(effectiveDate.orNull)
      .authenticatorVersion(
        authenticatorVersion.map(java.lang.Long.valueOf).orNull
      )
      .certificate(certificate.orNull)
      .url(url.orNull)
      .certificationDescriptor(certificationDescriptor.orNull)
      .certificateNumber(certificateNumber.orNull)
      .certificationPolicyVersion(certificationPolicyVersion.orNull)
      .certificationRequirementsVersion(certificationRequirementsVersion.orNull)
      .build()
  )

}
