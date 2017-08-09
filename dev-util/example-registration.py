#!/usr/bin/python3
#
# Scratchpad for working with raw U2F messages, useful for creating raw messages as test data.
# Example keys from secion 8.1 of
# https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#registration-example

from base64 import urlsafe_b64encode as b64encode
from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def hextokeys(private_key_hex, public_key_hex):
  s = int(private_key_hex, 16)
  x = int(public_key_hex[2:66], 16)
  y = int(public_key_hex[66:], 16)

  keynums = ec.EllipticCurvePrivateNumbers(s, ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()))
  private_key = keynums.private_key(default_backend())
  return (private_key, private_key.public_key())

def make_signature_base(application_parameter_hex, client_data_json, key_handle_hex, user_public_key_hex):
  challenge_parameter_hex = make_challenge_parameter_hex(client_data_json)
  return '00' + application_parameter_hex + challenge_parameter_hex + key_handle_hex + user_public_key_hex

def sign(private_key, message_hex):
  return private_key.sign(message_hex, sig_alg)

def make_challenge_parameter_hex(client_data_json):
  return sha256(bytes(client_data_json, 'UTF-8')).hex()

def make_registration_request_message(user_public_key_hex, key_handle_hex, attestation_certificate_hex, signature_hex):
  return '05' + user_public_key_hex + hex(len(key_handle_hex) // 2)[2:] + key_handle_hex + attestation_certificate_hex + signature_hex

def sha256(data):
  hasher = hashes.Hash(hashes.SHA256(), default_backend())
  hasher.update(data)
  return hasher.finalize()

def byteStringToDecimalBytes(data):
  return [int(b) for b in data]

def byteStringToDecimalSignedBytes(data):
  return [i if i < 128 else i - 256 for i in byteStringToDecimalBytes(data)]

sig_alg = ec.ECDSA(hashes.SHA256())

private_attestation_key_hex = 'f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664'
public_attestation_key_hex = '048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101'
attestation_certificate_hex = '3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df'

private_user_key_hex = '9a9684b127c5e3a706d618c86401c7cf6fd827fd0bc18d24b0eb842e36d16df1'
public_user_key_hex = '04b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9'
key_handle_hex = '2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25'

client_data = '{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}'

application_parameter_hex = 'f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4'

# 1 byte RFU = 0x00
# 32 bytes application parameter
# 32 bytes challenge parameter
# L bytes key handle
# 65 bytes user public key
example_signature_base_hex = make_signature_base(application_parameter_hex, client_data, key_handle_hex, public_user_key_hex)
example_signature_hex = '304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871'

# 1 reserved byte = 0x05
# 65 bytes user public key
# 1 byte key handle length = L
# L bytes key handle
# X.509 attestation certificate
# X bytes = above signature
example_response_message_hex = '05' + public_user_key_hex + '40' + key_handle_hex + attestation_certificate_hex + example_signature_hex



(private_attestation_key, public_attestation_key) = hextokeys(private_attestation_key_hex, public_attestation_key_hex)

(private_user_key, public_user_key) = hextokeys(private_user_key_hex, public_user_key_hex)

# Just ensure that we can successfully verify the example signature against the example key
public_attestation_key.verify(unhexlify(example_signature_hex), unhexlify(example_signature_base_hex), sig_alg)


different_client_data = '{"typ":"navigator.id.launchNukes","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","origin":"http://example.com"}'
different_challenge_parameter_hex = sha256(bytes(different_client_data, 'UTF-8')).hex()

public_attestation_key.verify(private_attestation_key.sign(b'Hello, World!', sig_alg), b'Hello, World!', sig_alg)

def print_results(private_user_key_hex, public_user_key_hex, private_attestation_key, application_parameter_hex, client_data_json, key_handle_hex, user_public_key_hex):
  signature_base_hex = make_signature_base(application_parameter_hex, client_data_json, key_handle_hex, user_public_key_hex)
  signature = sign(private_attestation_key, unhexlify(signature_base_hex))
  message = make_registration_request_message(public_user_key_hex, key_handle_hex, attestation_certificate_hex, signature.hex())

  public_attestation_key.verify(signature, unhexlify(signature_base_hex), sig_alg)

  print("Private key:\n ", private_user_key_hex)
  print("Public key:\n ", public_user_key_hex)
  print("App ID:\n ", application_parameter_hex)
  print("Client data:\n ", client_data_json)
  print("Data to sign:\n ", signature_base_hex)
  print("Signature:\n ", signature.hex())
  print("Registration request message:\n ", message)
  print("Registration request message Base64:\n ", b64encode(unhexlify(message)))

print_results(
  private_user_key_hex,
  public_user_key_hex,
  private_attestation_key,
  application_parameter_hex,
  different_client_data,
  key_handle_hex,
  public_user_key_hex
)
