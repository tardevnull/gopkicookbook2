package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

func main(){
	privateCaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	publicCaKey := privateCaKey.Public()

	//[RFC5280]
	subjectCa := pkix.Name{
		CommonName:         "ca01",
		OrganizationalUnit: []string{"Example Org Unit"},
		Organization:       []string{"Example Org"},
		Country:            []string{"JP"},
	}

	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subjectCa,
		NotAfter:              time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	//Self Sign CA Certificate
	caCertificate, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, publicCaKey, privateCaKey)

	//Convert to ASN.1 PEM encoded form
	var f *os.File
	f, err = os.Create("ca01.crt")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caCertificate})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	f, err = os.Create("ca01.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	derCaPrivateKey := x509.MarshalPKCS1PrivateKey(privateCaKey)

	err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derCaPrivateKey})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}


	privateSslKey, err := rsa.GenerateKey(rand.Reader, 2048)
	publicSslKey := privateSslKey.Public()

	subjectSsl := pkix.Name{
		CommonName:         "svr01",
		OrganizationalUnit: []string{"Example Org Unit"},
		Organization:       []string{"Example Org"},
		Country:            []string{"JP"},
	}

	sslTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(123),
		Subject:               subjectSsl,
		NotAfter:              time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"svr01.example.org"},
	}


	//SSL Certificate
	derSslCertificate, err := x509.CreateCertificate(rand.Reader, sslTpl, caTpl, publicSslKey, privateCaKey)
	//Convert to ASN.1 PEM encoded form
	f, err = os.Create("svr01.crt")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: derSslCertificate})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	f, err = os.Create("svr01.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	derPrivateSslKey := x509.MarshalPKCS1PrivateKey(privateSslKey)

	err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derPrivateSslKey})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}


	privateClientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	publicClientKey := privateClientKey.Public()

	//Client Certificate
	subjectClient := pkix.Name{
		CommonName:         "client01",
		OrganizationalUnit: []string{"Example Org Unit"},
		Organization:       []string{"Example Org"},
		Country:            []string{"JP"},
	}

	cliTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(456),
		Subject:               subjectClient,
		NotAfter:              time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	derClientCertificate, err := x509.CreateCertificate(rand.Reader, cliTpl, caTpl, publicClientKey, privateCaKey)

	cert, err := x509.ParseCertificate(derClientCertificate)

	f, err = os.Create("client01.p12")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//PKCS#12 [RFC7292] including client private keys, client certificates
	p12, err := pkcs12.Encode(rand.Reader, privateClientKey, cert, nil, "pincode")
	_, err = f.Write(p12)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

}