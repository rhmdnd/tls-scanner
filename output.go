package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func printClusterResults(results ScanResults) {
	fmt.Printf("=== CLUSTER SCAN RESULTS ===\n")
	fmt.Printf("Timestamp: %s\n", results.Timestamp)
	fmt.Printf("Total IPs: %d\n", results.TotalIPs)
	fmt.Printf("Successfully Scanned: %d\n", results.ScannedIPs)
	fmt.Printf("\n")

	for _, ipResult := range results.IPResults {
		fmt.Printf("-----------------------------------------------------\n")
		fmt.Printf("IP: %s\n", ipResult.IP)
		if ipResult.OpenshiftComponent != nil {
			fmt.Printf("Component: %s\n", ipResult.OpenshiftComponent.Component)
			fmt.Printf("Source Location: %s\n", ipResult.OpenshiftComponent.SourceLocation)
			fmt.Printf("Maintainer: %s\n", ipResult.OpenshiftComponent.MaintainerComponent)
			fmt.Printf("Is Bundle: %t\n", ipResult.OpenshiftComponent.IsBundle)
		}
		if len(ipResult.Services) > 0 {
			fmt.Printf("Services:\n")
			for _, service := range ipResult.Services {
				fmt.Printf("  - %s/%s (Type: %s", service.Namespace, service.Name, service.Type)
				if len(service.Ports) > 0 {
					fmt.Printf(", Ports: %v", service.Ports)
				}
				fmt.Printf(")\n")
			}
		}
		fmt.Printf("Status: %s\n", ipResult.Status)

		if ipResult.Error != "" {
			fmt.Printf("Error: %s\n", ipResult.Error)
			continue
		}

		if len(ipResult.OpenPorts) == 0 {
			fmt.Printf("No open ports found\n")
			continue
		}

		fmt.Printf("Open Ports: %v\n", ipResult.OpenPorts)
		fmt.Printf("\n")

		for _, portResult := range ipResult.PortResults {
			fmt.Printf("  Port %d:\n", portResult.Port)
			if portResult.Error != "" {
				fmt.Printf("    Error: %s\n", portResult.Error)
				continue
			}

			fmt.Printf("    Protocol: %s\n", portResult.Protocol)
			fmt.Printf("    State: %s\n", portResult.State)
			fmt.Printf("    Service: %s\n", portResult.Service)
			if portResult.ProcessName != "" {
				fmt.Printf("    Process Name: %s (%s)\n", portResult.ProcessName, portResult.ContainerName)
			}

			if len(portResult.TlsVersions) > 0 {
				fmt.Printf("    TLS Versions: %s\n", strings.Join(portResult.TlsVersions, ", "))
			}
			if len(portResult.TlsCiphers) > 0 {
				fmt.Printf("    Ciphers:\n")
				for _, cipher := range portResult.TlsCiphers {
					strength := portResult.TlsCipherStrength[cipher]
					if strength != "" {
						fmt.Printf("      %s - %s\n", cipher, strength)
					} else {
						fmt.Printf("      %s\n", cipher)
					}
				}
			}
			fmt.Printf("\n")
		}
	}
}

func printParsedResults(results ScanResults) {
	if len(results.IPResults) == 0 {
		log.Println("No hosts were scanned or host is down.")
		return
	}

	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			fmt.Printf("PORT    STATE SERVICE REASON\n")
			fmt.Printf("%d/%s %-5s %-7s %s\n", portResult.Port, portResult.Protocol, portResult.State, portResult.Service, portResult.Reason)

			if len(portResult.TlsVersions) > 0 || len(portResult.TlsCiphers) > 0 {
				fmt.Println("| ssl-enum-ciphers:")
				for _, version := range portResult.TlsVersions {
					fmt.Printf("|   %s:\n", version)
				}
				if len(portResult.TlsCiphers) > 0 {
					fmt.Printf("|   ciphers:\n")
					for _, cipher := range portResult.TlsCiphers {
						strength := portResult.TlsCipherStrength[cipher]
						if strength != "" {
							fmt.Printf("|     %s - %s\n", cipher, strength)
						} else {
							fmt.Printf("|     %s\n", cipher)
						}
					}
				}
			}
		}
	}
}

func writeJSONOutput(data interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	log.Printf("JSON output written to: %s", filename)
	return nil
}

func writeJUnitOutput(scanResults ScanResults, filename string) error {
	testSuite := JUnitTestSuite{
		Name: "TLSSecurityScan",
	}

	for _, ipResult := range scanResults.IPResults {
		for _, portResult := range ipResult.PortResults {
			testCase := JUnitTestCase{
				Name:      fmt.Sprintf("%s:%d - %s", ipResult.IP, portResult.Port, portResult.Service),
				ClassName: ipResult.Pod.Name,
			}

			var failures []string
			if portResult.IngressTLSConfigCompliance != nil && (!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				failures = append(failures, "Ingress TLS config is not compliant.")
			}
			if portResult.APIServerTLSConfigCompliance != nil && (!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				failures = append(failures, "API Server TLS config is not compliant.")
			}
			if portResult.KubeletTLSConfigCompliance != nil && (!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				failures = append(failures, "Kubelet TLS config is not compliant.")
			}

			if len(failures) > 0 {
				testCase.Failure = &JUnitFailure{
					Message: "TLS Compliance Failed",
					Type:    "TLSComplianceCheck",
					Content: strings.Join(failures, "\n"),
				}
				testSuite.Failures++
			}

			testSuite.TestCases = append(testSuite.TestCases, testCase)
		}
	}

	testSuite.Tests = len(testSuite.TestCases)

	// Create the directory for the file if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create directory for JUnit report: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create JUnit report file: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(xml.Header); err != nil {
		return fmt.Errorf("failed to write XML header to JUnit report: %v", err)
	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(testSuite); err != nil {
		return fmt.Errorf("could not encode JUnit report: %v", err)
	}

	return nil
}
