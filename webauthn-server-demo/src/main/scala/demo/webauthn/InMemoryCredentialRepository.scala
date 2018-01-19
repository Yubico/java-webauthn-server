package demo.webauthn

import java.util
import java.util.Optional

import com.fasterxml.jackson.core.JsonProcessingException
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.util.WebAuthnCodecs
import org.slf4j.LoggerFactory

import scala.util.Failure
import scala.util.Success
import scala.util.Try

object InMemoryCredentialRepository {
  private val logger = LoggerFactory.getLogger(classOf[InMemoryCredentialRepository])
}

class InMemoryCredentialRepository extends CredentialRepository {
  final private val keyStorage = new util.HashMap[String, CredentialRegistration]

  override def lookup(credentialId: String, userHandle: Optional[String]): Optional[RegisteredCredential] = {
    val registration = keyStorage.get(credentialId)

    InMemoryCredentialRepository.logger.debug(s"lookup credential ID: ${credentialId}, user handle: ${userHandle}; result: ${registration}")

    if (registration == null)
      None.asJava
    else {
      val cose = registration.getRegistration.publicKeyCose
      val key = WebAuthnCodecs.importCoseP256PublicKey(cose)
      if (key == null) {
        val coseString: String = Try(WebAuthnCodecs.json.writeValueAsString(cose)) match {
          case Success(s) => s
          case Failure(e: JsonProcessingException) =>
            "(Failed to write as string)"
        }
        InMemoryCredentialRepository.logger.error(s"Failed to decode public key in storage: ID: ${credentialId} COSE: ${coseString}")
      }
      Optional.of(
        new RegisteredCredential(
          credentialId = registration.getRegistration.keyId.id,
          publicKey = key,
          signatureCount = registration.getSignatureCount,
          userHandle = U2fB64Encoding.decode(registration.getUserHandleBase64)
        )
      )
    }
  }

  def add(keyId: String, key: CredentialRegistration): Unit = {
    InMemoryCredentialRepository.logger.debug(s"add ${keyId} : ${key}")
    keyStorage.put(keyId, key)
  }

  def remove(keyId: String): CredentialRegistration = {
    InMemoryCredentialRepository.logger.debug("remove {}", keyId)
    keyStorage.remove(keyId)
  }
}
