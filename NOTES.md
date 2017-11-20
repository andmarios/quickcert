## Commands useful to debug

Read a CRL:

    openssl crl -inform PEM -text -noout -in [crl.pem]

Verify CRL:

    cat CAcrt.pem crl.pem > ca-crt-crl.pem
    openssl verify -crl_check -verbose -CAfile ca-crt-crl.pem crt.pem

View certificate info:

    openssl x509 -noout -text -in crt.pem
