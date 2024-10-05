package main

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/lazybark/cert-generator/pkg/gen"
)

func main() {
	for {
		if err := CLIGenerate(); err != nil {
			log.Printf("%v\n", err)
		}

		log.Println("########################################################")
	}
}

func CLIGenerate() error {
	scanner := bufio.NewScanner(os.Stdin)

	orgName := prompt(scanner, "Org -> ")
	host := prompt(scanner, "Host ('localhost' if empty) -> ")
	if host == "" {
		host = "localhost"
	}

	lifetime, err := promptInt(scanner, "Lifetime (days) -> ")
	if err != nil {
		return fmt.Errorf("[CLIGenerate] failed to convert days number -> %w", err)
	}

	usageArrayX509, err := promptKeyUsages(scanner)
	if err != nil {
		return fmt.Errorf("[CLIGenerate] %w", err)
	}

	addrsArrayIPs, err := promptIPAddresses(scanner)
	if err != nil {
		return fmt.Errorf("[CLIGenerate] %w", err)
	}

	certPath := prompt(scanner, fmt.Sprintf("Certificate path ('%s' if empty) -> ", gen.GetDefaultCertPath()))
	if certPath == "" {
		certPath = gen.GetDefaultCertPath()
	}

	keyPath := prompt(scanner, fmt.Sprintf("Key path ('%s' if empty) -> ", gen.GetDefaultKeyPath()))
	if keyPath == "" {
		keyPath = gen.GetDefaultKeyPath()
	}

	err = gen.Generator(keyPath, certPath, orgName, host, addrsArrayIPs, lifetime, usageArrayX509)
	if err != nil {
		return fmt.Errorf("[CLIGenerate] failed to generate certificate -> %w", err)
	}

	fmt.Printf("Generated certificate: %s\n", certPath)
	fmt.Printf("Generated private key: %s\n", keyPath)

	return nil
}

func prompt(scanner *bufio.Scanner, message string) string {
	fmt.Print(message)
	scanner.Scan()

	return scanner.Text()
}

func promptInt(scanner *bufio.Scanner, message string) (int, error) {
	fmt.Print(message)
	scanner.Scan()

	return strconv.Atoi(scanner.Text())
}

func promptKeyUsages(scanner *bufio.Scanner) ([]x509.ExtKeyUsage, error) {
	fmt.Printf("External key usage, e.g. '1,2,3' (%v=any, %v=server, %v=client, %v=code sign, %v=email protection, %v=IPSECEndSystem, %v=IPSECTunnel, %v=IPSECUser, %v=time stamping, %v=OCSP signing, %v=MicrosoftServerGatedCrypto, %v=NetscapeServerGatedCrypto, %v=MicrosoftCommercialCodeSigning, %v=MicrosoftKernelCodeSigning) -> ",
		x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel, x509.ExtKeyUsageIPSECUser, x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
	scanner.Scan()

	usageArray := strings.Split(scanner.Text(), ",")

	var usageArrayX509 []x509.ExtKeyUsage

	for _, v := range usageArray {
		conv, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("failed to convert usage -> %w", err)
		}

		usageArrayX509 = append(usageArrayX509, x509.ExtKeyUsage(conv))
	}

	return usageArrayX509, nil
}

func promptIPAddresses(scanner *bufio.Scanner) ([]net.IP, error) {
	fmt.Print("Enter IP addresses, e.g. '192.168.0.1,127.0.0.1' -> ")
	scanner.Scan()

	addrsArray := strings.Split(scanner.Text(), ",")

	var addrsArrayIPs []net.IP

	for _, v := range addrsArray {
		conv := net.ParseIP(v)
		if conv == nil {
			return nil, fmt.Errorf("invalid IP address: %s", v)
		}

		addrsArrayIPs = append(addrsArrayIPs, conv)
	}

	return addrsArrayIPs, nil
}
