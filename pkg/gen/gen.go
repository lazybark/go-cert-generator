package gen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func Generator(keyPath string, certPath string, orgName string, host string, addresses []net.IP, lifetime int, usageArrayX509 []x509.ExtKeyUsage) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("[Generator] failed to generate private key -> %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("[Generator] failed to generate serial number -> %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		DNSNames:              []string{host},
		IPAddresses:           addresses,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usageArrayX509,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("[Generator] failed to create certificate -> %w", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return errors.New("[Generator] failed to encode certificate to PEM")
	}
	if err := os.WriteFile(certPath+".pem", pemCert, 0644); err != nil {
		return err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("[Generator] unable to marshal private key -> %w", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return errors.New("[Generator] failed to encode key to PEM")
	}
	if err := os.WriteFile(keyPath+".pem", pemKey, 0600); err != nil {
		return err
	}

	return nil
}
