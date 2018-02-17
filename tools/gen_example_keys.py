#!/usr/bin/python3

import OpenSSL

key = OpenSSL.crypto.PKey()
key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

encoded_certs = []
for algo, digest_algo in (("MD5", "SHA256"),
                          ("SHA1", "SHA256"),
                          ("SHA256", "SHA256"),
                          ("SHA512", "SHA512")):

    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(1)
    cert.set_notBefore(b"20000101000000Z")
    cert.set_notAfter(b"21000101000000Z")
    cert.set_pubkey(key)
    cert.sign(key, algo)
    cert.get_subject().C = b"FN"
    cert.get_subject().O = b"Example Association"
    cert.get_subject().CN = b"aiosasl tests"
    cert.set_issuer(cert.get_subject())
    encoded_certs.append((
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert),
        cert.digest(digest_algo)
    ))

print(encoded_certs)
