package com.yubico.webauthn.test

import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.UserIdentity

import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption

object Helpers {

  object CredentialRepository {
    val empty = new CredentialRepository {
      override def getCredentialIdsForUsername(
          username: String
      ): java.util.Set[PublicKeyCredentialDescriptor] = Set.empty.asJava
      override def getUserHandleForUsername(
          username: String
      ): Optional[ByteArray] = None.toJava
      override def getUsernameForUserHandle(
          userHandle: ByteArray
      ): Optional[String] = None.toJava
      override def lookup(
          credentialId: ByteArray,
          userHandle: ByteArray,
      ): Optional[RegisteredCredential] = None.toJava
      override def lookupAll(
          credentialId: ByteArray
      ): java.util.Set[RegisteredCredential] = Set.empty.asJava
    }
    val unimplemented = new CredentialRepository {
      override def getCredentialIdsForUsername(
          username: String
      ): java.util.Set[PublicKeyCredentialDescriptor] = ???
      override def getUserHandleForUsername(
          username: String
      ): Optional[ByteArray] = ???
      override def getUsernameForUserHandle(
          userHandleBase64: ByteArray
      ): Optional[String] = ???
      override def lookup(
          credentialId: ByteArray,
          userHandle: ByteArray,
      ): Optional[RegisteredCredential] = ???
      override def lookupAll(
          credentialId: ByteArray
      ): java.util.Set[RegisteredCredential] = ???
    }

    def withUser(
        user: UserIdentity,
        credential: RegisteredCredential,
    ): CredentialRepository =
      new CredentialRepository {
        override def getCredentialIdsForUsername(
            username: String
        ): java.util.Set[PublicKeyCredentialDescriptor] =
          if (username == user.getName)
            Set(
              PublicKeyCredentialDescriptor
                .builder()
                .id(credential.getCredentialId)
                .build()
            ).asJava
          else Set.empty.asJava
        override def getUserHandleForUsername(
            username: String
        ): Optional[ByteArray] =
          if (username == user.getName)
            Some(user.getId).toJava
          else None.toJava
        override def getUsernameForUserHandle(
            userHandle: ByteArray
        ): Optional[String] =
          if (userHandle == user.getId)
            Some(user.getName).toJava
          else None.toJava
        override def lookup(
            credentialId: ByteArray,
            userHandle: ByteArray,
        ): Optional[RegisteredCredential] =
          if (
            credentialId == credential.getCredentialId && userHandle == user.getId
          )
            Some(credential).toJava
          else None.toJava
        override def lookupAll(
            credentialId: ByteArray
        ): java.util.Set[RegisteredCredential] =
          if (credentialId == credential.getCredentialId)
            Set(credential).asJava
          else Set.empty.asJava
      }
  }

  def toRegisteredCredential(
      user: UserIdentity,
      result: RegistrationResult,
  ): RegisteredCredential =
    RegisteredCredential
      .builder()
      .credentialId(result.getKeyId.getId)
      .userHandle(user.getId)
      .publicKeyCose(result.getPublicKeyCose)
      .build()

}
