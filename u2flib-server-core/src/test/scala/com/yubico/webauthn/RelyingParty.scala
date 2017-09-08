package com.yubico.webauthn

import java.util.Optional

import com.yubico.scala.util.JavaConverters._
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

import scala.util.Try


class RelyingParty (
  val rp: RelyingPartyIdentity,
  val challengeGenerator: ChallengeGenerator,
  val preferredPubkeyParams: Seq[PublicKeyCredentialParameters],
  val origin: String,
  val authenticatorRequirements: Optional[AuthenticatorSelectionCriteria] = None.asJava,
  val crypto: Crypto = new BouncyCastleCrypto,
  val allowSelfAttestation: Boolean = false,
) {

  def startRegistration(
    user: UserIdentity,
    excludeCredentials: Optional[Seq[PublicKeyCredentialDescriptor]] = None.asJava,
    extensions: Optional[AuthenticationExtensions] = None.asJava,
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
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava,
  ): Try[PublicKeyCredentialDescriptor] =
    _finishRegistration(request, response, callerTokenBindingId).run

  private[webauthn] def _finishRegistration(
    request: MakePublicKeyCredentialOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava,
  ): FinishRegistrationSteps =
    FinishRegistrationSteps(
      request = request,
      response = response,
      callerTokenBindingId = callerTokenBindingId,
      origin = origin,
      rp = rp,
      crypto = crypto,
      allowSelfAttestation = allowSelfAttestation,
    )

}
