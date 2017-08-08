#!/usr/bin/python3
#
# Scratchpad for working with raw U2F messages, useful for creating raw messages as test data.
# Example keys from secion 8.2 of
# https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#authentication-response-message-success

from binascii import hexlify, unhexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sig_alg = ec.ECDSA(hashes.SHA256())

private_key_hex = 'ffa1e110dde5a2f8d93c4df71e2d4337b7bf5ddb60c75dc2b6b81433b54dd3c0'
public_key_hex = '04d368f1b665bade3c33a20f1e429c7750d5033660c019119d29aa4ba7abc04aa7c80a46bbe11ca8cb5674d74f31f8a903f6bad105fb6ab74aefef4db8b0025e1d'

example_payload_hex = '4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca0100000001ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57'
example_signature_hex = '304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f'

s = int(private_key_hex, 16)
x = int(public_key_hex[2:66], 16)
y = int(public_key_hex[66:], 16)

keynums = ec.EllipticCurvePrivateNumbers(s, ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()))
private_key = keynums.private_key(default_backend())
public_key = private_key.public_key()

# Just ensure that we can successfully verify the example signature against the example key
public_key.verify(unhexlify(example_signature_hex), unhexlify(example_payload_hex), sig_alg)


# Successful authentication message, but with invalid user presence byte
payload_hex = '4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca0000000001ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57'
payload_signature = private_key.sign(unhexlify(payload_hex), sig_alg)

print("Private key:", private_key_hex)
print("Public key:", public_key_hex)
print("Signing payload:", payload_hex)
print("Signature:", hexlify(payload_signature))
