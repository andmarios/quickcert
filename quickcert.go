// Copyright (c) 2015-2019, Marios Andreopoulos. All rights reserved.
// Use of this source code is governed by a BSD-style license that
// can be found in the LICENSE file that should come with this code.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	CAcertFile     = flag.String("cacert", "CAcrt.pem", "path to CA certificate")
	CAkeyFile      = flag.String("cakey", "CAkey.pem", "path to CA key file")
	outFile        = flag.String("out", "", "Prefix to output files (key.pem, crt.pem or crl.pem)")
	encryptKey     = flag.Bool("encrypt-key", false, "Encrypt the private key")
	host           = flag.String("hosts", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom      = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor       = flag.Float64("duration", 365.25, "Duration in days that certificate is valid for")
	isCA           = flag.Bool("ca", false, "The cert will be self-signed and set as its own CA (ignores cacert and cakey)")
	crlDistrPoints = flag.String("crl-dp", "", "Comma-separated Certificate Revocation List Distribution Endpoints (optional, set it at CA level to propagate to client certs)")
	rsaBits        = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve     = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521")
	chain          = flag.Bool("chain", false, "If set the CA cert will be appended to the certificate file")
	cnAttr         = flag.String("CN", "", "Certificate attribute: Common Name, as in 'example.com'")
	cAttr          = flag.String("C", "Ankh-Morpork", "Certificate attribute: Country")
	oAttr          = flag.String("O", "Unseen University", "Certificate attribute: Organization")
	ouAttr         = flag.String("OU", "Library", "Certificate attribute: Organizational Unit")
	email          = flag.String("emails", "", "Comma-separated emails to be added to the certificate")
	appendCRL      = flag.String("append-to-crl", "", "If provided when creating a CRL, the certificate will be added to this list.")
	revokeCert     = flag.String("revoke-cert", "", "If provided, will create a CRL for this cerficate.")
	printVersion   = flag.Bool("version", false, "Print version and exit")
)

// publicKey detects the type of key and returns its PublicKey
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// pemBlockForKey returns a marshaled private key
// according to its type
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// read_and_decode_pem takes a path to a pem encoded key,
// reads it and decodes it
func readDecodePemFile(file string) (*pem.Block, error) {
	// Read the file
	in, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	// Decode the PEM encoded data
	data, _ := pem.Decode(in)
	if data == nil {
		return nil, errors.New("bad pem data, not PEM-encoded")
	}
	return data, nil
}

func checkError(msg string, err error) {
	if err != nil {
		log.Fatal(msg, err.Error())
	}
}

func readPassword(msg string) ([]byte, error) {
	fmt.Print(msg)
	password, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return password, nil
}

func userConfirmation(msg string) error {
ASK_CONFIRMATION:
	var response = ""
	fmt.Print(msg)
	_, _ = fmt.Scanln(&response)
	switch strings.ToLower(response) {
	case "y", "":
		return nil
	case "n":
		return errors.New("interrupted by user")
	default:
		goto ASK_CONFIRMATION
	}
}

func main() {
	flag.Parse()

	if *printVersion {
		fmt.Println("Quickcert v" + version)
		fmt.Println("https://github.com/andmarios/quickcert")
		os.Exit(0)
	}

	if len(*host) == 0 && !*isCA && len(*revokeCert) == 0 {
		fmt.Println("If you are not creating a CA pair, you need to set the -hosts parameter. Use -h for help.")
		os.Exit(1)
	}

	if *isCA && len(*revokeCert) > 0 {
		fmt.Println("A self-signed Certificate Authority cannot have itself revoked!")
		os.Exit(1)
	}

	if len(*host) > 0 && len(*revokeCert) > 0 {
		fmt.Println("You asked to both create a cert-key pair (option -hosts enforce this) and to")
		fmt.Println("create a certificate revocation list. These options are incompatible.")
		os.Exit(1)
	}

	var cacert *x509.Certificate
	var cacertpem *pem.Block
	var cakey interface{}
	var err error

	// If not CA, read the CA key and cert
	if !*isCA {
		// Read CAcert
		log.Println("Reading CA certificate")
		data, err := readDecodePemFile(*CAcertFile)
		checkError("Could not read ca key file: ", err)
		cacert, err = x509.ParseCertificate(data.Bytes)
		checkError("Could not parse CA certificate: ", err)
		cacertpem = data

		// Read CAkey
		log.Println("Reading CA private key")
		data, err = readDecodePemFile(*CAkeyFile)
		checkError("Could not read ca key file: ", err)

		// If encrypted, decrypt it
		if x509.IsEncryptedPEMBlock(data) {
			password, err := readPassword("CA key is encrypted\nEnter password: ")
			checkError("Error reading CA private key password: ", err)
			data.Bytes, err = x509.DecryptPEMBlock(data, []byte(password))
			checkError("Could not decrypt CA private key: ", err)
		}

		// Detect type and parse key
		if data.Type == "RSA PRIVATE KEY" {
			cakey, err = x509.ParsePKCS1PrivateKey(data.Bytes)
			checkError("Could not parse CA RSA private key: ", err)
		} else if data.Type == "EC PRIVATE KEY" {
			cakey, err = x509.ParseECPrivateKey(data.Bytes)
			checkError("Could not parse CA ECDSA key: ", err)
		} else {
			log.Fatalf("Could not find a compatible private key type (%s), only RSA and ECDSA are accepted", data.Type)
		}
	}

	if len(*revokeCert) > 0 {
		var revokedCerts []pkix.RevokedCertificate
		if len(*appendCRL) > 0 {
			log.Println("Reading CLR")
			if _, err := os.Stat(*appendCRL); os.IsNotExist(err) {
				log.Println("CLR file does not exist, will create new: " + *appendCRL)
			} else {
				data, err := readDecodePemFile(*appendCRL)
				checkError("Could not read CRL file: ", err)
				crl, err := x509.ParseCRL(data.Bytes)
				checkError("Could not parse CRL: ", err)
				revokedCerts = append(revokedCerts, crl.TBSCertList.RevokedCertificates...)
			}
		}
		log.Println("Reading Certificate to Revoke")
		data, err := readDecodePemFile(*revokeCert)
		checkError("Could not read certificate file: ", err)
		cert, err := x509.ParseCertificate(data.Bytes)
		checkError("Could not parse certificate: ", err)

		pool := x509.NewCertPool()
		pool.AddCert(cacert)
		opts := x509.VerifyOptions{Roots: pool}
		_, err = cert.Verify(opts)
		checkError("The certificate you want to revoke wasn't signed by this CA: ", err)

		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
		})

		crlDerBytes, err := cacert.CreateCRL(rand.Reader, cakey, revokedCerts, time.Now(), time.Now().AddDate(0, 1, 0))
		checkError("Failed to create CRL: ", err)

		var outCrl string
		if len(*appendCRL) > 0 {
			outCrl = *appendCRL
		} else {
			outCrl = "crl.pem"
		}
		if _, err := os.Stat(outCrl); err == nil {
			checkError("CRL file exists: ",
				userConfirmation("Certificate file ("+outCrl+") exists. Overwrite? [Yn]: "))
		}

		// Save CRL to file
		log.Println("Writing CRL file: " + outCrl)
		crlOut, err := os.Create(outCrl)
		checkError("Failed to open "+outCrl+" for writing: ", err)
		pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: crlDerBytes})
		crlOut.Close()
		os.Exit(0)
	}

	// Create new key
	log.Println("Generating private key. This may take some time, depending on type and length.")
	var privkey interface{}
	switch *ecdsaCurve {
	case "":
		if *rsaBits < 2048 && !*isCA {
			log.Println("Consider upgrading your key to 2048 bits or better.")
		} else if *rsaBits < 4096 && *isCA {
			log.Println("Consider upgrading your CA key 4096 bits.")
		}
		privkey, err = rsa.GenerateKey(rand.Reader, *rsaBits)
		// I disabled P224 curve because Redhat patched their golang to
		// not support this curve due to patent law reasons.
		// I could leave it, but then quickcert won't compile on centos, rhel and fedora
		//	case "P224":
		//		privkey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		privkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		privkey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		privkey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized elliptic curve: %q", *ecdsaCurve)
	}
	checkError("Failed to generate private key: ", err)

	// Create certificate
	log.Println("Generating certificate.")
	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		checkError("Failed to parse creation date: ", err)
	}

	// time.Duration takes nanoseconds    |nsec in a day|
	duration := time.Duration(*validFor * 24 * 3600 * 1e9)
	notAfter := notBefore.Add(duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	checkError("Failed to generate serial number: ", err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{},
			Organization:       []string{},
			OrganizationalUnit: []string{},
			CommonName:         "",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if len(*cnAttr) > 0 {
		template.Subject.CommonName = *cnAttr
	}
	if len(*cAttr) > 0 {
		template.Subject.Country = append(template.Subject.Country, *cAttr)
	}
	if len(*oAttr) > 0 {
		template.Subject.Organization = append(template.Subject.Organization, *oAttr)
	}
	if len(*ouAttr) > 0 {
		template.Subject.OrganizationalUnit = append(template.Subject.OrganizationalUnit, *ouAttr)
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	if len(*email) > 0 {
		emails := strings.Split(*email, ",")
		for _, e := range emails {
			template.EmailAddresses = append(template.EmailAddresses, e)
		}
	}

	var crlDistributionPoints []string
	if len(*crlDistrPoints) > 0 {
		crlDistributionPoints = strings.Split(*crlDistrPoints, ",")
	}
	if !*isCA && len(cacert.CRLDistributionPoints) > 0 {
		crlDistributionPoints = append(crlDistributionPoints, cacert.CRLDistributionPoints...)
	}
	if len(crlDistributionPoints) > 0 {
		template.CRLDistributionPoints = append(template.CRLDistributionPoints, crlDistributionPoints...)
	}

	if *isCA {
		cakey = privkey
		cacert = &template
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	// Sign certificate
	log.Println("Signing certificate")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cacert, publicKey(privkey), cakey)
	checkError("Failed to create certificate: ", err)

	// Check if files to be written exist
	outCrt := *outFile + "crt.pem"
	outKey := *outFile + "key.pem"
	if _, err := os.Stat(outCrt); err == nil {
		checkError("Certificate file exists: ",
			userConfirmation("Certificate file ("+outCrt+") exists. Overwrite? [Yn]: "))
	}
	if _, err := os.Stat(outKey); err == nil {
		checkError("Key file exists: ",
			userConfirmation("Key file ("+outKey+") exists. Overwrite? [Yn]: "))
	}

	// Save certificate to file
	log.Println("Writing certificate file: ", outCrt)
	certOut, err := os.Create(outCrt)
	checkError("Failed to open "+outCrt+" for writing: ", err)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if *chain {
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cacertpem.Bytes})
	}
	certOut.Close()

	// Save private key to file
	log.Println("Writing key file: ", outKey)
	keyOut, err := os.OpenFile(outKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	checkError("Failed to open key.pem for writing:", err)

	keyPemBlock := pemBlockForKey(privkey)
	if *encryptKey {
	ASK_KEY:
		pass1, err := readPassword("Enter password for private key: ")
		checkError("Error reading private key password, attempt 1: ", err)
		pass2, err := readPassword("Please re-enter password for private key: ")
		checkError("Error reading private key password, attempt 2: ", err)
		if string(pass1) == string(pass2) {
			keyPemBlock, err = x509.EncryptPEMBlock(rand.Reader, keyPemBlock.Type, keyPemBlock.Bytes, pass1, x509.PEMCipher3DES)
		} else {
			fmt.Println("Passwords mismatch. Try again.")
			goto ASK_KEY
		}
	}
	pem.Encode(keyOut, keyPemBlock)
	keyOut.Close()

	log.Println("Files written succesfully. Exiting.")
}
