// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn

import java.security.cert.X509Certificate

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.WebAuthnCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.RegistrationExtensionInputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs

import scala.collection.JavaConverters._


object RegistrationTestDataGenerator extends App {
  regenerateTestData()

  def printTestDataCode(
    credential: PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs],
    caCert: Option[X509Certificate]
  ): Unit = {
    for { caCert <- caCert } {
      println(s"""attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("${BinaryUtil.toHex(caCert.getEncoded)}"))),""")
    }
    println(s"""attestationObject = new ByteArray(BinaryUtil.fromHex("${credential.getResponse.getAttestationObject.getHex}")),
               |clientDataJson = \"\"\"${new String(credential.getResponse.getClientDataJSON.getBytes, "UTF-8")}\"\"\"
               |
               |
               """.stripMargin)
  }

  def regenerateTestData(): Unit = {
    val td = RegistrationTestData
    for { testData <- List(
      td.FidoU2f.BasicAttestation,
      td.FidoU2f.SelfAttestation,
      td.NoneAttestation.Default,
      td.Packed.BasicAttestation,
      td.Packed.BasicAttestationWithoutAaguidExtension,
      td.Packed.BasicAttestationWithWrongAaguidExtension,
      td.Packed.SelfAttestation,
      td.Packed.SelfAttestationWithWrongAlgValue
    ) } {
      val (cred, cert) = testData.regenerate()
      printTestDataCode(cred, cert)
    }
  }
}

object RegistrationTestData {
  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  object AndroidKey {
    val BasicAttestation: RegistrationTestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-key")
  }
  object AndroidSafetynet {
    val BasicAttestation: RegistrationTestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-safetynet")
  }
  object FidoU2f {

    val BasicAttestation: RegistrationTestData = new RegistrationTestData(
      attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("308201d63082017da00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200048a551913988ee12c2330b4d3a503607defd0ca1eb5f44edf8a4cee2d48df692efbeeb3e9749bbddd960483b6fa930f49ee45318f0de4e014ad07b54b5d88a862a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402202ab9e33dd3fcaee34bfe44f370656b73ccd591bbf1a41b01ee3fb83a3b8fd83f022036b95c02cfa90b751c93612f487a3773fc2b85276de059bc972ad0a47ed3304d"))),
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020e50fe8ab67d1e773463decf62cfe9a9d5928ece4fd98a013b80478301bb8e29ea5225820d06403b07cf09311ca10b2478979deaaad9c65751e749c503fe9fb935686fcae03260102215820bfa61c3ae256f6a887d2ae9b2075b5246896ba9f44a2a6874ab746acfe7db9e3200163666d74686669646f2d7532666761747453746d74bf63783563815901eb308201e73082018ca00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200040bd659232377a4f910fdcfccaec55511d00beacbdf417f49c9de938137f98df03971b3553bc11a2bd4ef5089ed290d15cc84e005443c794b13dc5e230916c591a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d04030203490030460221008546464190caa7a603cd5c8dd60f30a23a9d227ca69603c1421c179092d8e4a1022100891b766c83b9def81518e354db14068d0ade9c8651927b347f4a63454b12add36373696758473045022100c88c93d88194e183f5522ec471a77f8a78d82fa7f99292f8d5f0c20cec6277d702203e289df8dd0568d9bd0b7d294fd30afcf3b264f5fb63f3163b46bb725c8fb31fffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "fido-u2f") }

    val SelfAttestation: RegistrationTestData = new RegistrationTestData(
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00205558386f4ed61a6c98a3fed94060fff66808947953754a0dff2aea9ae2164635a52258208d05cb87cec921d5e6fbc22c32a07fb35ed89c19a3f0a2866fcf4a248194e650032601022158202bb1c0846fca809059b41272f0c2953d733b31b50c14453b7a9855b7bfc98229200163666d74686669646f2d7532666761747453746d74bf63783563815901e7308201e330820189a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200042bb1c0846fca809059b41272f0c2953d733b31b50c14453b7a9855b7bfc982298d05cb87cec921d5e6fbc22c32a07fb35ed89c19a3f0a2866fcf4a248194e650a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020348003045022100a91c5499a6518bc59648bde7e7467488736e1ae82b5eb85c14957a0f82d23dfc02205a4b9963f88dbabaa0fa298eae6f0876b9f5e65650c4bd29f1f3f7eeb1312c24637369675847304502205af7085152ec65cc5ee097c5890316e6cac286379c32925a969ab414b013aa59022100b9b9d56cf4314e10c13caa57fb1fb0a01e87ffdec623c62637fddf56a8c4c62cffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "fido-u2f") }

  }
  object NoneAttestation {
    val Default = new RegistrationTestData(
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f002082e7622c8c35a5786e66815f44a82b954628df497361169e77af23bb9bea1b69a5225820ae947a15818d883351ac00b957ad794c4b0206e2df34ec7b52969016a215800e03260102215820763f33278817151fad81d172493b8826c3a736cb1acf884e38c26fbe65c2438a200163666d74646e6f6e656761747453746d74bfffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createUnattestedCredential() }
  }
  object Packed {

    val BasicAttestation: RegistrationTestData = new RegistrationTestData(
      attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("308201d63082017da00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000474d182bbb3aaab864ac3e0c7e93d3f3eb65299cf36ed0ea7795d4da0246f517bd3d6ef2a8a359246ea78734f6bd71c4bd6394e499e658815415edc0d14b43735a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402206429f7885dc57981fba4e12a1e4e415cb27c0228dc824231b123bc7cbb3ee0ae02202b89913cacff206d9ea7d6246c6b5fa8d7949bc157ad364d9f754b783d660109"))),
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00203479233993ce33d113bca341cbff7b17f8da6477f4f052067eee7431a741cf33a5225820930d76c61326ca11ebac918dd4374a652177739519b45e1d12484d1c815714690326010221582077c8934918d445fb70c2371f5d132693adf2ac90ba7609809e53ee24efaff148200163666d74667061636b65646761747453746d74bf63736967584730450220192f0fb8fa4488bb62f1712f0cb35b2e27cecedae5c81fbb220989c851ced05a022100bcb5d4dcccd30360490bcbd843fdb1cdd5d2e5acd78665c87e46bac865b9543063783563815901ea308201e63082018ca00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004f09bbbfa47bfaf423f143154763b25373f3d9d94af225a1a1629df5a5ff75034d23e015902e0c97dfc1ace1c2821907d8fe090b50c39aad032596b88fd6068efa32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d04030203480030450220186f6aba1f39dd8431f566e7993ee8928ac365f88475bfad2c783da69d93b59402210091f8b72046427284ad51ef1068b4892795d21bdcdc14e625b4ecfccb166f4172ffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "packed") }

    val BasicAttestationWithoutAaguidExtension: RegistrationTestData = new RegistrationTestData(
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020b5d7943ea57b200148e0d87b735269ee2c09108087916b0dab1aabb0f78599cda5225820619f68d30b6c4dddf73f4dbb86d4585f06d0b0d2c8978b5d351ffa2e5c060d54032601022158208c68e6bc94460133d137d0bd11eea5067512ed470f6f479f0ba699052959d822200163666d74667061636b65646761747453746d74bf637369675846304402205f52f52e3f44618945f542646a3c459e6438abe2ef036ed8daef223d164ab338022077cdb39f441957215d8b7d68c7f697d0a121bd7e17ddbc341cad2d713bbbe25d63783563815901bf308201bb30820162a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004bc0bd10e9f28f94715aca7dc586100a5fb6fa442ae2038a5f6f3667d5f9a134d8e1dc2aa55a6f56dfb44b2456028d64540ec2aaba78226593fe544884f4d7c65300a06082a8648ce3d0403020347003044022028f69c5ab6cb118296305743d3781840552eaf54bd01803cb857e6b07ed77ec402201a3efb279c314b5eba4635d0c62ba3d81703b63061c5b603df80b39ac4088218ffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(TestAuthenticator.generateAttestationCertificate(extensions = Nil)), attestationStatementFormat = "packed") }

    val BasicAttestationWithWrongAaguidExtension: RegistrationTestData = new RegistrationTestData(
      attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("308201d63082017da00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004caa58b4a5bbcca24c5e398e4653dafb882a327960ccb72963bf62fa2a1c03f82671b11f0cccb1e1c476125f04afae64b5d1f4f7a6fb5bd1abecd18eeab9d5126a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020347003044022072f6ae460c82ffe89f9ad1f1bd188ba0c3b50540e02edda0a99c37c6efe2fab5022038754e4e088f0e749946975eab9017eeebb621e830ab853119aae1998e750ab2"))),
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000005390f0e0d0c0b0a09080706050403020100002028856c20f5018aaffce3835765cc58ae6c73e37d37acde80f0aa1611602fa815a52258200348c1c7f2fd5dc658252f7865ebbde62ce968c03e9d97988612809f5abbbe7503260102215820a9342b20b06f71fd8b7b0e7ade89ab438c0d9f541edacedbf0d43f9494d06874200163666d74667061636b65646761747453746d74bf637369675846304402205b1ee9a9def2fb631423fec4c02fa132a5562ad1a32ea4b3edaf8300fd920bd1022069799c95206c10a7a50a36a14bc990a25a54c48ba62c73af55ec8c117329170b63783563815901e9308201e53082018ca00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004ecc94d2f374915a217b9558ed6746f40ebc3de98e953742d2a7963288cbaf017506988d24b8caf1ec728008c70b749f513007106913c39828772d75b0591db03a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020347003044022013c65c197c02e710acca16da432659c16313a1e19f2d8a3e9d47ee22cedc57a702205373349d9a58e8d7170032a2b64dd056d24d84dded75fac0002375a27037ee73ffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(aaguid = new ByteArray(Array(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)), attestationStatementFormat = "packed") }

    val SelfAttestation: RegistrationTestData = new RegistrationTestData(
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020fa616cbe1c046d224524e773b386f9f3fd0d0fb6d4c20700023288034e48f093a52258208b02052aeec1d7cfaf1244d9b72296a6bfaf9542c132273c4be8fc01388ee8f30326010221582081906607ef7095eaa3dea2517cfc5a7c0c9768685e30ddb5865f2ada0f5cc63c200163666d74667061636b65646761747453746d74bf6373696758473045022010511b27bd566c7bcdf6e4f08ef2fe4ea20a56826b76761253bbcc31b0be1fa2022100b2659e3efc858fd4389dc48cd0651487f2e7bc4f5eba59db154bdcd0ae60c9d163616c6726ffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed") }

    val SelfAttestationWithWrongAlgValue = new RegistrationTestData(
      attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00203022c626739f52e583ac292c31b80b80759d546f9956a5baf65216faae61313da52258202f752354da475fb5f6c0d35fef2ed8eea3e6dbf225c08b7fed567e813ae41402032601022158207fc7d8d3d5e8dce8bbfda0395f89f0d3c9ea0d9de1d6e62d0f0df9db7661cb9b200163666d74667061636b65646761747453746d74bf6373696758463044022078cf79efde68909ee2518b8feeb727b17a689db2e4b9d13dc3a34e9c46b9390002201e94861f46b7f19f5df5bedef08f91fb862e5eb07c23e6c3b28151917f3e5c2963616c67390100ffff")),
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.create","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed", alg = Some(COSEAlgorithmIdentifier.RS256)) }
  }
  object Tpm {
    val PrivacyCa: RegistrationTestData = Packed.SelfAttestation.editAttestationObject("fmt", "tpm")
  }
}

case class RegistrationTestData(
  attestationObject: ByteArray,
  clientDataJson: String,
  authenticatorSelection: Option[AuthenticatorSelectionCriteria] = None,
  clientExtensionResults: ClientRegistrationExtensionOutputs = ClientRegistrationExtensionOutputs.builder().build(),
  overrideRequest: Option[PublicKeyCredentialCreationOptions] = None,
  requestedExtensions: RegistrationExtensionInputs = RegistrationExtensionInputs.builder().build(),
  rpId: RelyingPartyIdentity = RelyingPartyIdentity.builder().id("localhost").name("Test party").build(),
  userId: UserIdentity = UserIdentity.builder().name("test@test.org").displayName("Test user").id(new ByteArray(Array(42, 13, 37))).build(),
  attestationCaCert: Option[X509Certificate] = None
) {
  def regenerate(): (PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs], Option[X509Certificate]) = null

  def clientDataJsonBytes: ByteArray = new ByteArray(clientDataJson.getBytes("UTF-8"))
  def clientData = new CollectedClientData(clientDataJsonBytes)
  def clientDataJsonHash: ByteArray = new BouncyCastleCrypto().hash(clientDataJsonBytes)
  def aaguid: ByteArray = new AttestationObject(attestationObject).getAuthenticatorData.getAttestedCredentialData.get.getAaguid
  def packedAttestationCert: X509Certificate =
    CertificateParser.parseDer(
      new AttestationObject(attestationObject)
        .getAttestationStatement
        .get("x5c")
        .get(0)
        .binaryValue
    )

  def editClientData[A <: JsonNode](updater: ObjectNode => A): RegistrationTestData = copy(
    clientDataJson = WebAuthnCodecs.json.writeValueAsString(
      updater(WebAuthnCodecs.json.readTree(clientDataJson).asInstanceOf[ObjectNode])
    )
  )

  def editClientData[A <: JsonNode](name: String, value: A): RegistrationTestData = editClientData { clientData: ObjectNode =>
    clientData.set(name, value)
  }
  def editClientData(name: String, value: String): RegistrationTestData = editClientData(name, RegistrationTestData.jsonFactory.textNode(value))
  def responseChallenge: ByteArray = clientData.getChallenge

  def editClientData(name: String, value: ByteArray): RegistrationTestData =
    editClientData(
      name,
      RegistrationTestData.jsonFactory.textNode(value.getBase64Url)
    )

  def editAttestationObject[A <: JsonNode](name: String, value: A): RegistrationTestData = copy(
    attestationObject = new ByteArray(WebAuthnCodecs.cbor.writeValueAsBytes(
      WebAuthnCodecs.cbor.readTree(attestationObject.getBytes).asInstanceOf[ObjectNode]
        .set(name, value)
    ))
  )

  def editAttestationObject(name: String, value: String): RegistrationTestData =
    editAttestationObject(name, RegistrationTestData.jsonFactory.textNode(value))

  def editAuthenticatorData(updater: ByteArray => ByteArray): RegistrationTestData = {
    val attObj: ObjectNode = WebAuthnCodecs.cbor.readTree(attestationObject.getBytes).asInstanceOf[ObjectNode]
    val authData: ByteArray = new ByteArray(attObj.get("authData").binaryValue)
    editAttestationObject("authData", RegistrationTestData.jsonFactory.binaryNode(updater(authData).getBytes))
  }

  def request: PublicKeyCredentialCreationOptions = overrideRequest getOrElse PublicKeyCredentialCreationOptions.builder()
      .rp(rpId)
      .user(userId)
      .challenge(clientData.getChallenge)
      .pubKeyCredParams(List(PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.ES256).build()).asJava)
      .extensions(requestedExtensions)
      .authenticatorSelection(authenticatorSelection.asJava)
      .build()

  def response: PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs] = PublicKeyCredential.builder()
    .id(new AttestationObject(attestationObject).getAuthenticatorData.getAttestedCredentialData.get.getCredentialId)
    .response(
      AuthenticatorAttestationResponse.builder()
        .attestationObject(attestationObject)
        .clientDataJSON(clientDataJsonBytes)
        .build()
    )
    .clientExtensionResults(clientExtensionResults)
    .build()
}
