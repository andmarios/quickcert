# quickcert #

**Quickcert** implements a tiny subset of `openssl x509` command.

Its purpose is to help me create quickly a custom CA, as well as signed certificates with any setting needed for deployment. Usually this adds to many hostnames and/or IP addresses and a certificate that includes the parent certificate (chain).

## Usage

In general you should create first a CA:

    quickcert -ca -out "RootCA-" -rsa-bits 4096 -duration 3652 -encrypt-key

This will create you CA key (`RootCA-key.pem`) and your CA certificate (`RootCA-crt.pem`).

Then you can create sets of private key and certificates to use with your applications:

    quickcert -cacert RootCA-crt.pem -cakey RootCA-key.pem -hosts localhost,127.0.0.1 -duration 365 -chain -out "app-"

This will create an unencrypted private key (`app-key.pem`) and a certificate (`app-crt.pem`) that includes the CA certificate as wanted by the golang SSL/TLS implementation, nginx and other software.

There are other options too:

    quickcert -h

## Limitations

Of course you can use any externally created CA private key - certificate pair. But your CA certificate file should contain only your CA certificate. Chained CA certificates are supported yet.
