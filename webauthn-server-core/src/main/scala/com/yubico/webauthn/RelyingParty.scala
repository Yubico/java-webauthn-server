package com.yubico.webauthn

import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.attestation.MetadataService
import com.yubico.u2f.crypto.ChallengeGenerator
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.crypto.Crypto
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions

import scala.util.Try


class RelyingParty (
  val rp: RelyingPartyIdentity,
  val challengeGenerator: ChallengeGenerator,
  val preferredPubkeyParams: java.util.List[PublicKeyCredentialParameters],
  val origins: java.util.List[String],
  val authenticatorRequirements: Optional[AuthenticatorSelectionCriteria] = None.asJava,
  val crypto: Crypto = new BouncyCastleCrypto,
  val allowUntrustedAttestation: Boolean = false,
  val credentialRepository: CredentialRepository,
  val metadataService: Optional[MetadataService] = None.asJava,
  val validateSignatureCounter: Boolean = true,
  val validateTypeAttribute: Boolean = true
) {

  def startRegistration(
    user: UserIdentity,
    excludeCredentials: Optional[java.util.Collection[PublicKeyCredentialDescriptor]] = None.asJava,
    extensions: Optional[AuthenticationExtensions] = None.asJava
  ): MakePublicKeyCredentialOptions =
    MakePublicKeyCredentialOptions(
      rp = rp,
      user = user,
      challenge = challengeGenerator.generateChallenge().toVector,
      pubKeyCredParams = preferredPubkeyParams,
      excludeCredentials = excludeCredentials,
      authenticatorSelection = authenticatorRequirements,
      extensions = extensions
    )

  def finishRegistration(
    request: MakePublicKeyCredentialOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
    credentialRepository: CredentialRepository,
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava
  ): Try[RegistrationResult] =
    _finishRegistration(request, response, credentialRepository, callerTokenBindingId).run

  private[webauthn] def _finishRegistration(
    request: MakePublicKeyCredentialOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
    credentialRepository: CredentialRepository,
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava
  ): FinishRegistrationSteps =
    FinishRegistrationSteps(
      request = request,
      response = response,
      callerTokenBindingId = callerTokenBindingId,
      credentialRepository = credentialRepository,
      origins = origins,
      rpId = rp.id,
      crypto = crypto,
      allowUntrustedAttestation = allowUntrustedAttestation,
      metadataService = metadataService,
      validateTypeAttribute = validateTypeAttribute
    )

  def startAssertion(
    allowCredentials: Optional[java.util.List[PublicKeyCredentialDescriptor]] = None.asJava,
    extensions: Optional[AuthenticationExtensions] = None.asJava
  ): PublicKeyCredentialRequestOptions =
    PublicKeyCredentialRequestOptions(
      rpId = Some(rp.id).asJava,
      challenge = challengeGenerator.generateChallenge().toVector,
      allowCredentials = allowCredentials,
      extensions = extensions
    )

  def finishAssertion(
    request: PublicKeyCredentialRequestOptions,
    response: PublicKeyCredential[AuthenticatorAssertionResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava
  ): Try[Boolean] =
    _finishAssertion(request, response, callerTokenBindingId).run

  private[webauthn] def _finishAssertion(
    request: PublicKeyCredentialRequestOptions,
    response: PublicKeyCredential[AuthenticatorAssertionResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava
  ): FinishAssertionSteps =
    FinishAssertionSteps(
      request = request,
      response = response,
      callerTokenBindingId = callerTokenBindingId,
      origins = origins,
      rpId = rp.id,
      crypto = crypto,
      credentialRepository = credentialRepository,
      validateSignatureCounter = validateSignatureCounter,
      validateTypeAttribute = validateTypeAttribute
    )

}
