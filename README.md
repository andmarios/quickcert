# quickcert #

**Quickcert** implements a tiny subset of `openssl x509` command.

Its purpose is to help me create quickly a custom CA, as well as signed certificates
with any setting needed for deployment. Usually this adds to many hostnames and/or
IP addresses and a certificate that includes the parent certificate (chain).

## Usage

In general you should create first a CA:

    quickcert -ca -out "RootCA-" -rsa-bits 4096 -duration 3652 -encrypt-key

This will create you CA key (`RootCA-key.pem`) and your CA certificate¹ (`RootCA-crt.pem`).

Then you can create sets of private key and certificates to use with your applications:

    quickcert -cacert RootCA-crt.pem -cakey RootCA-key.pem -hosts localhost,127.0.0.1 -chain -out "app-"

This will create an unencrypted private key (`app-key.pem`) and a certificate (`app-crt.pem`)
that includes the CA certificate as wanted by the golang SSL/TLS implementation, nginx
and other software.

There are other options too:

    quickcert -h

For example you could set some attributes:

    quickcert -cacert RootCA-crt.pem -cakey RootCA-key.pem -hosts 127.0.0.1 -C "Ankh-Morpork" -O "Unseen University" -OU "Library" -CN "Ook" -duration 730.5

**1:** Ideally you will install your CA certificate into your system. This is fairly
complicated but in short, for Linux systems, you would do something like:

    sudo mkdir /usr/local/share/ca-certificates
    sudo cp RootCA-crt.pem /usr/local/share/ca-certificates/RootCA.crt
    sudo update-ca-certificates --fresh

### Revokation

To revoke a certificate, you need a copy of it. It's a good idea to keep a copy
of all the certificates you create —but not of the private keys.

To create, or add a certificate to a Certificate Revocation List (CRL) run:

    quickcert -cacert RootCA-crt.pem -cakey RootCA-key.pem -revoke-cert client.crt.pem -append-to-crl CRL.pem

As an example, you can add `CRL.pem` to your OpenVPN server to deny access to
revoked clients.

## Installation

The go way:

    go get github.com/andmarios/quickcert

If you use Gentoo, there is an [ebuild available](https://github.com/andmarios/ebuilds_backyard/tree/master/app-crypt/quickcert).

## Limitations

Of course you can use any externally created CA private key - certificate pair. But
your CA certificate file should contain only your CA certificate. Chained CA
certificates aren't supported yet.

## Bugs

If you press CTRL+C while `quickcert` is waiting for password input, you will return to
your terminal with echo set off. Despite my attempts to handle this —and apparently
<golang.org/x/crypto/ssh/terminal/util.go>'s ReadPassword also tries to handle this—
I couldn't find a solution.

Not a bug but a limitation, code could use better organisation. After the addition
of revocation lists supports, the current code structure shows its elementary
initial design.

## Trivia

Default duration is 365.25 days since this is closer to the real duration of a year.

## License

You can find more information inside the `LICENSE` file. In short this software uses
a BSD 3-Clause license.

## Attribution

Parts of the code come from [generate_cert.go](http://golang.org/src/crypto/tls/generate_cert.go)
example from golang's source code. Since I wanted to learn about golang's crypto and x509 and
practice in go, I started with a simple version of my own that only read, created and signed RSA
based private keys and certificates, then started copying blocks from `generate_cert.go` (replacing
mine simple ones) and adding features.
