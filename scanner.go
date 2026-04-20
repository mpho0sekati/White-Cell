package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Target   string            `json:"target"`
	OpenPorts []int            `json:"open_ports"`
	Banners  map[string]string `json:"banners"`
}

func scanPort(target string, port int, results chan<- map[string]interface{}, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Properly format the address for both IPv4 and IPv6
	var address string
	ip := net.ParseIP(target)
	if ip != nil && ip.To4() == nil && ip.To16() != nil {
		// This is an IPv6 address, wrap it in brackets
		address = fmt.Sprintf("[%s]:%d", target, port)
	} else {
		// This is an IPv4 address or hostname
		address = fmt.Sprintf("%s:%d", target, port)
	}
	
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// Try to grab the banner
	banner := grabBanner(conn)
	
	result := map[string]interface{}{
		"port":    port,
		"is_open": true,
		"banner":  banner,
	}
	
	results <- result
}

func grabBanner(conn net.Conn) string {
	// Set a deadline for reading the banner
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	
	// Attempt to read the banner
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		// If we can't read a banner, just return a generic service indicator
		return ""
	}
	
	banner := strings.TrimSpace(string(buffer[:n]))
	
	// Clean up the banner string
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.TrimSpace(banner)
	
	// Limit the banner length to prevent overly large responses
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}
	
	return banner
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <domain_or_ip>\n", os.Args[0])
		os.Exit(1)
	}
	
	target := os.Args[1]
	
	// Validate that the target is a valid domain/IP
	ip := net.ParseIP(target)
	if ip == nil {
		// If it's not an IP, try to resolve it
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			fmt.Fprintf(os.Stderr, "Error resolving target: %v\n", err)
			os.Exit(1)
		}
		// Use the first resolved IP
		target = ips[0].String()
	}
	
	ports := []int{21, 22, 80, 443, 3306, 8080}
	
	var wg sync.WaitGroup
	resultsChan := make(chan map[string]interface{}, len(ports))
	
	openPorts := []int{}
	banners := make(map[string]string)
	
	// Launch goroutines for each port
	for _, port := range ports {
		wg.Add(1)
		go scanPort(target, port, resultsChan, &wg)
	}
	
	// Close the results channel when all goroutines finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Collect results
	for result := range resultsChan {
		port := result["port"].(int)
		isOpen := result["is_open"].(bool)
		
		if isOpen {
			openPorts = append(openPorts, port)
			
			banner := result["banner"].(string)
			if banner != "" {
				banners[strconv.Itoa(port)] = banner
			} else {
				// Identify service based on port if no banner available
				service := getServiceByPort(port)
				if service != "" {
					banners[strconv.Itoa(port)] = service
				}
			}
		}
	}
	
	// Sort the open ports
	for i := 0; i < len(openPorts)-1; i++ {
		for j := i + 1; j < len(openPorts); j++ {
			if openPorts[i] > openPorts[j] {
				openPorts[i], openPorts[j] = openPorts[j], openPorts[i]
			}
		}
	}
	
	// Prepare the final result
	result := ScanResult{
		Target:    os.Args[1], // Original target from arguments
		OpenPorts: openPorts,
		Banners:   banners,
	}
	
	// Output as JSON
	jsonData, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println(string(jsonData))
}

func getServiceByPort(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 3306:
		return "MySQL"
	case 8080:
		return "HTTP-Alt"
	default:
		return ""
	}
}