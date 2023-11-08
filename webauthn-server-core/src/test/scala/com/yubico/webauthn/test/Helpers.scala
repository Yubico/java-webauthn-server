package com.yubico.webauthn.test

import com.yubico.webauthn.CredentialRecord
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.CredentialRepositoryV2
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.RegistrationTestData
import com.yubico.webauthn.UsernameRepository
import com.yubico.webauthn.data.AuthenticatorTransport
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.UserIdentity

import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption

object Helpers {

  def toJava(o: Option[scala.Boolean]): Optional[java.lang.Boolean] =
    o.toJava.map((b: scala.Boolean) => b)

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

  object CredentialRepositoryV2 {
    def empty[C <: CredentialRecord] =
      new CredentialRepositoryV2[C] {
        override def getCredentialDescriptorsForUserHandle(
            userHandle: ByteArray
        ): java.util.Set[PublicKeyCredentialDescriptor] = Set.empty.asJava
        override def lookup(
            credentialId: ByteArray,
            userHandle: ByteArray,
        ): Optional[C] = None.toJava
        override def credentialIdExists(
            credentialId: ByteArray
        ): Boolean = false
      }
    def unimplemented[C <: CredentialRecord] =
      new CredentialRepositoryV2[C] {
        override def getCredentialDescriptorsForUserHandle(
            userHandle: ByteArray
        ): java.util.Set[PublicKeyCredentialDescriptor] = ???
        override def lookup(
            credentialId: ByteArray,
            userHandle: ByteArray,
        ): Optional[C] = ???
        override def credentialIdExists(
            credentialId: ByteArray
        ): Boolean = ???
      }

    class CountingCalls[C <: CredentialRecord](inner: CredentialRepositoryV2[C])
        extends CredentialRepositoryV2[C] {
      var getCredentialIdsCount = 0
      var lookupCount = 0
      var credentialIdExistsCount = 0

      override def getCredentialDescriptorsForUserHandle(
          userHandle: ByteArray
      ): java.util.Set[PublicKeyCredentialDescriptor] = {
        getCredentialIdsCount += 1
        inner.getCredentialDescriptorsForUserHandle(userHandle)
      }

      override def lookup(
          credentialId: ByteArray,
          userHandle: ByteArray,
      ): Optional[C] = {
        lookupCount += 1
        inner.lookup(credentialId, userHandle)
      }

      override def credentialIdExists(credentialId: ByteArray) = {
        credentialIdExistsCount += 1
        inner.credentialIdExists(credentialId)
      }
    }

    def withUsers[C <: CredentialRecord](
        users: (UserIdentity, C)*
    ): CredentialRepositoryV2[C] = {
      new CredentialRepositoryV2[C] {
        override def getCredentialDescriptorsForUserHandle(
            userHandle: ByteArray
        ): java.util.Set[PublicKeyCredentialDescriptor] =
          users
            .filter({
              case (u, c) =>
                u.getId == userHandle && c.getUserHandle == userHandle
            })
            .map({
              case (_, credential) =>
                PublicKeyCredentialDescriptor
                  .builder()
                  .id(credential.getCredentialId)
                  .transports(credential.getTransports)
                  .build()
            })
            .toSet
            .asJava

        override def lookup(
            credentialId: ByteArray,
            userHandle: ByteArray,
        ): Optional[C] =
          users
            .find(_._1.getId == userHandle)
            .map(_._2)
            .filter(cred =>
              cred.getUserHandle == userHandle && cred.getCredentialId == credentialId
            )
            .toJava

        override def credentialIdExists(
            credentialId: ByteArray
        ): Boolean =
          users.exists(_._2.getCredentialId == credentialId)
      }
    }

    def withUser(
        user: UserIdentity,
        credentialId: ByteArray,
        publicKeyCose: ByteArray,
        signatureCount: Long = 0,
        be: Option[Boolean] = None,
        bs: Option[Boolean] = None,
    ): CredentialRepositoryV2[CredentialRecord] = {
      withUsers(
        (
          user,
          credentialRecord(
            credentialId = credentialId,
            userHandle = user.getId,
            publicKeyCose = publicKeyCose,
            signatureCount = signatureCount,
            be = be,
            bs = bs,
          ),
        )
      )
    }
  }

  object UsernameRepository {
    val empty =
      new UsernameRepository {
        override def getUserHandleForUsername(
            username: String
        ): Optional[ByteArray] = None.toJava
        override def getUsernameForUserHandle(
            userHandle: ByteArray
        ): Optional[String] = None.toJava
      }
    def unimplemented[C <: CredentialRecord] =
      new UsernameRepository {
        override def getUserHandleForUsername(
            username: String
        ): Optional[ByteArray] = ???
        override def getUsernameForUserHandle(
            userHandle: ByteArray
        ): Optional[String] = ???
      }

    def withUsers(users: UserIdentity*): UsernameRepository =
      new UsernameRepository {
        override def getUserHandleForUsername(
            username: String
        ): Optional[ByteArray] =
          users.find(_.getName == username).map(_.getId).toJava

        override def getUsernameForUserHandle(
            userHandle: ByteArray
        ): Optional[String] =
          users.find(_.getId == userHandle).map(_.getName).toJava
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

  def credentialRecord(
      credentialId: ByteArray,
      userHandle: ByteArray,
      publicKeyCose: ByteArray,
      signatureCount: Long = 0,
      transports: Option[Set[AuthenticatorTransport]] = None,
      be: Option[Boolean] = None,
      bs: Option[Boolean] = None,
  ): CredentialRecord = {
    new CredentialRecord {
      override def getCredentialId: ByteArray = credentialId
      override def getUserHandle: ByteArray = userHandle
      override def getPublicKeyCose: ByteArray = publicKeyCose
      override def getSignatureCount: Long = signatureCount
      override def getTransports
          : Optional[java.util.Set[AuthenticatorTransport]] =
        transports.toJava.map(_.asJava)
      override def isBackupEligible: Optional[java.lang.Boolean] = toJava(be)
      override def isBackedUp: Optional[java.lang.Boolean] = toJava(bs)
    }
  }

  def toCredentialRecord(
      testData: RegistrationTestData,
      signatureCount: Long = 0,
      be: Option[Boolean] = None,
      bs: Option[Boolean] = None,
  ): CredentialRecord =
    new CredentialRecord {
      override def getCredentialId: ByteArray = testData.response.getId
      override def getUserHandle: ByteArray = testData.userId.getId
      override def getPublicKeyCose: ByteArray =
        testData.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
      override def getSignatureCount: Long = signatureCount
      override def isBackupEligible: Optional[java.lang.Boolean] = toJava(be)
      override def isBackedUp: Optional[java.lang.Boolean] = toJava(bs)
    }

}
