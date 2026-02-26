package main

import (
	"encoding/json"
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

func writeOutputFiles(results ScanResults, artifactDir, jsonFile, csvFile, junitFile string) {
	if jsonFile == "" && csvFile == "" && junitFile == "" {
		return
	}

	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		log.Fatalf("Could not create artifact directory %s: %v", artifactDir, err)
	}
	log.Printf("Artifacts will be saved to: %s", artifactDir)

	if jsonFile != "" {
		jsonPath := jsonFile
		if !filepath.IsAbs(jsonPath) {
			jsonPath = filepath.Join(artifactDir, jsonFile)
		}
		if err := writeJSONOutput(results, jsonPath); err != nil {
			log.Printf("Error writing JSON output: %v", err)
		} else {
			log.Printf("JSON results written to: %s", jsonPath)
		}
	}

	if csvFile != "" {
		csvPath := csvFile
		if !filepath.IsAbs(csvPath) {
			csvPath = filepath.Join(artifactDir, csvFile)
		}
		if err := writeCSVOutput(results, csvPath); err != nil {
			log.Printf("Error writing CSV output: %v", err)
		} else {
			log.Printf("CSV results written to: %s", csvPath)
		}

		if len(results.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + "_errors.csv"
			if err := writeScanErrorsCSV(results, errorFilename); err != nil {
				log.Printf("Error writing scan errors CSV: %v", err)
			} else {
				log.Printf("Scan errors written to: %s", errorFilename)
			}
		}
	}

	if junitFile != "" {
		junitPath := junitFile
		if !filepath.IsAbs(junitPath) {
			junitPath = filepath.Join(artifactDir, junitFile)
		}
		if err := writeJUnitOutput(results, junitPath); err != nil {
			log.Printf("Error writing JUnit XML output: %v", err)
		} else {
			log.Printf("JUnit XML results written to: %s", junitPath)
		}
	}
}
