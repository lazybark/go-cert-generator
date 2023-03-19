package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	for {
		err := CLIGenerate()
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		fmt.Println("########################################################")
	}
}

func CLIGenerate() error {
	// Provide user data
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Provide cert data:")
	// Org
	fmt.Print("Org -> ")
	scanner.Scan()
	orgName := scanner.Text()
	// Host
	fmt.Print("Host ('localhost' if empty) -> ")
	scanner.Scan()
	host := scanner.Text()
	// Lifetime
	fmt.Print("Lifetime (days) -> ")
	scanner.Scan()
	lifetime, err := strconv.Atoi(scanner.Text())
	if err != nil {
		return fmt.Errorf("[CLIGenerate] failed convert days number -> %w", err)
	}
	// Key usage
	fmt.Printf("External key usage, e.g. '1,2,3' (%v=any, %v=server, %v=client, %v=code sign,, %v=email protection, %v=IPSECEndSystem, %v=IPSECTunnel, %v=IPSECUser, %v=time stamping, %v=OCSP signing, %v=MicrosoftServerGatedCrypto, %v=NetscapeServerGatedCrypto, %v=MicrosoftCommercialCodeSigning, %v=MicrosoftKernelCodeSigning)-> ",
		x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel, x509.ExtKeyUsageIPSECUser, x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
	scanner.Scan()
	usage := scanner.Text()

	// Convert strings into ints
	usageArray := strings.Split(usage, ",")
	var usageArrayInt []int
	for _, v := range usageArray {
		conv, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("[CLIGenerate] failed convert usage -> %w", err)
		}
		usageArrayInt = append(usageArrayInt, conv)
	}
	// Make proper usages
	var usageArrayX509 []x509.ExtKeyUsage
	for _, v := range usageArrayInt {
		usageArrayX509 = append(usageArrayX509, x509.ExtKeyUsage(v))
	}

	// Path
	fmt.Print("Certificate path ('cert.pem' if empty) -> ")
	scanner.Scan()
	certPath := scanner.Text()
	fmt.Print("Key path ('key.pem' if empty) -> ")
	scanner.Scan()
	keyPath := scanner.Text()

	err = Generator(keyPath, certPath, orgName, host, lifetime, usageArrayX509)
	if err != nil {
		return err
	}
	fmt.Printf("Generated certificate: %s.pem\n", certPath)
	fmt.Printf("Generated private key: %s.pem\n", keyPath)

	return nil
}

func Generator(keyPath string, certPath string, orgName string, host string, lifetime int, usageArrayX509 []x509.ExtKeyUsage) error {
	if keyPath == "" {
		keyPath = "key"
	}
	if certPath == "" {
		certPath = "cert"
	}
	if host == "" {
		host = "localhost"
	}

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
