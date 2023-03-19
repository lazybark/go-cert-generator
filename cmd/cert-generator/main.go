package main

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lazybark/cert-generator/pkg/gen"
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
	if host == "" {
		host = "localhost"
	}
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
	if certPath == "" {
		certPath = "cert"
	}

	fmt.Print("Key path ('key.pem' if empty) -> ")
	scanner.Scan()
	keyPath := scanner.Text()
	if keyPath == "" {
		keyPath = "key"
	}

	err = gen.Generator(keyPath, certPath, orgName, host, lifetime, usageArrayX509)
	if err != nil {
		return err
	}
	fmt.Printf("Generated certificate: %s.pem\n", certPath)
	fmt.Printf("Generated private key: %s.pem\n", keyPath)

	return nil
}
