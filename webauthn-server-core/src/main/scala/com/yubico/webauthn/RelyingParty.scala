package com.yubico.webauthn

import java.util.Optional
import java.util.function.Supplier

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.attestation.MetadataService
import com.yubico.u2f.crypto.ChallengeGenerator
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AuthenticationExtensionsClientInputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.AttestationConveyancePreference
import com.yubico.webauthn.data.RegistrationResult
import com.yubico.webauthn.data.AssertionResult
import com.yubico.webauthn.data.AssertionRequest

import scala.util.Try


class RelyingParty (
  val rp: RelyingPartyIdentity,
  val challengeGenerator: ChallengeGenerator,
  val preferredPubkeyParams: java.util.List[PublicKeyCredentialParameters],
  val origins: java.util.List[String],
  val attestationConveyancePreference: Optional[AttestationConveyancePreference] = None.asJava,
  val crypto: Crypto = new BouncyCastleCrypto,
  val allowMissingTokenBinding: Boolean = false,
  val allowUnrequestedExtensions: Boolean = false,
  val allowUntrustedAttestation: Boolean = false,
  val credentialRepository: CredentialRepository,
  val metadataService: Optional[MetadataService] = None.asJava,
  val validateSignatureCounter: Boolean = true,
  val validateTypeAttribute: Boolean = true
) {

  def startRegistration(
    user: UserIdentity,
    excludeCredentials: Optional[java.util.Collection[PublicKeyCredentialDescriptor]] = None.asJava,
    extensions: Optional[AuthenticationExtensionsClientInputs] = None.asJava,
    requireResidentKey: Boolean = false
  ): PublicKeyCredentialCreationOptions =
    PublicKeyCredentialCreationOptions(
      rp = rp,
      user = user,
      challenge = challengeGenerator.generateChallenge().toVector,
      pubKeyCredParams = preferredPubkeyParams,
      excludeCredentials = excludeCredentials,
      authenticatorSelection = Optional.of(AuthenticatorSelectionCriteria(requireResidentKey = requireResidentKey)),
      attestation = attestationConveyancePreference.asScala getOrElse AttestationConveyancePreference.default,
      extensions = extensions
    )

  def finishRegistration(
    request: PublicKeyCredentialCreationOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava
  ): Try[RegistrationResult] =
    _finishRegistration(request, response, callerTokenBindingId).run

  private[webauthn] def _finishRegistration(
    request: PublicKeyCredentialCreationOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
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
      allowMissingTokenBinding = allowMissingTokenBinding,
      allowUnrequestedExtensions = allowUnrequestedExtensions,
      allowUntrustedAttestation = allowUntrustedAttestation,
      metadataService = metadataService,
      validateTypeAttribute = validateTypeAttribute
    )

  def startAssertion(
    username: Optional[String],
    allowCredentials: Optional[java.util.List[PublicKeyCredentialDescriptor]] = None.asJava,
    extensions: Optional[AuthenticationExtensionsClientInputs] = None.asJava
  ): AssertionRequest =
    AssertionRequest(
      requestId = U2fB64Encoding.encode(challengeGenerator.generateChallenge()),
      username = username,
      publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions(
        rpId = Some(rp.id).asJava,
        challenge = challengeGenerator.generateChallenge().toVector,
        allowCredentials = (
          allowCredentials.asScala
            orElse
              username.asScala.map(un =>
                credentialRepository.getCredentialIdsForUsername(un))
        ).asJava,
        extensions = extensions
      )
    )

  def finishAssertion(
    request: AssertionRequest,
    response: PublicKeyCredential[AuthenticatorAssertionResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava
  ): Try[AssertionResult] =
    _finishAssertion(request, response, callerTokenBindingId).run

  private[webauthn] def _finishAssertion(
    request: AssertionRequest,
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
      allowMissingTokenBinding = allowMissingTokenBinding,
      allowUnrequestedExtensions = allowUnrequestedExtensions,
      validateSignatureCounter = validateSignatureCounter,
      validateTypeAttribute = validateTypeAttribute
    )

}
