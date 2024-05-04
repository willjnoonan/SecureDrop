from cryptoUtil import cryptoUtil

crypto = cryptoUtil()

#crypto.create_self_signed_cert("CA/CA_cert.pem", "CA/CA_key.pem")

#crypto.create_cert_signed_by_ca("CA/CA_cert.pem", "CA/CA_key.pem", "serverKeys/certificate.pem", "serverKeys/key.pem")
crypto.create_cert_signed_by_ca("CA/CA_cert.pem", "CA/CA_key.pem", "clientKeys/certificate.pem", "clientKeys/key.pem")