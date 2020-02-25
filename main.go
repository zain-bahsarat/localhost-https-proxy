package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/zain-bahsarat/minica"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// AppPort is default port for app
const AppPort = 80

// DefaultHostFilePath Default path of host file
const DefaultHostFilePath = "/etc/hosts"

// DataFolderName holds the data i.e. certificates, source domain list etc
const DataFolderName = ".prm-data"

// CertificateNamePrefix name used for key and certificate
const CertificateNamePrefix = "prm"

// LocalhostIP is the ip where the server will be running
const LocalhostIP = "127.0.0.1"

func getAppAddress() string {
	return fmt.Sprintf(":%d", AppPort)
}

func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	log.Println("handling request...")
	target := "http://192.168.99.100:8001"

	url, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(url)

	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))

	proxy.ServeHTTP(res, req)
}

func main() {
	pm := ProxyManager{DataFolder: DataFolderName}
	setup(&pm)
	startServer(&pm)
}

func handleMux(mux *http.ServeMux, pm *ProxyManager) {

	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		res.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		target := "https://example.com"

		if t, ok := pm.ProxyMap[req.Host]; ok {
			target = t
		} else {
			res.WriteHeader(404)
			fmt.Fprint(res, "404 - Page not found")
		}
		
		url, err := url.Parse(target)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		proxy := httputil.NewSingleHostReverseProxy(url)

		req.URL.Host = url.Host
		req.URL.Scheme = "http"
		
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))

		proxy.ServeHTTP(res, req)
	})
}

func startServer(pm *ProxyManager) {
	mux := http.NewServeMux()
	handleMux(mux, pm)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Fatal(srv.ListenAndServeTLS(pm.TLSCertPath, pm.TLSKeyPath))

}

// ProxyManagerOptions stores the flag values + internal option
type ProxyManagerOptions struct {
	InputProxyFilePath string
	SSLEnabled         bool
}

// ProxyManager will manage the routing logic
type ProxyManager struct {
	ProxyMap          map[string]string
	DataFolder        string
	TLSRootCertPath   string
	TLSRootKeyPath    string
	TLSCertPath       string
	TLSKeyPath        string
	TLSDomainListFile string
	Options           ProxyManagerOptions
}

// GetSourceDomains list of all source domains
func (pm *ProxyManager) GetSourceDomains() []string {

	sourceDomains := make([]string, 0)
	for k := range pm.ProxyMap {
		sourceDomains = append(sourceDomains, k)
	}

	return sourceDomains
}

// SetupDataFolder creates data folder if needed
func (pm *ProxyManager) SetupDataFolder() {

	curDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error.")
		os.Exit(1)
	}

	path := curDir + "/" + pm.DataFolder
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 0777)
	}
}

// GetCertificateDomains returns the list of domains used in certificate
func (pm *ProxyManager) GetCertificateDomains() []string {
	path := pm.GetDataFolderPath() + "/.certificate-domain-list"

	fileContent, err := ReadFile(path)
	if err != nil {
		return []string{}
	}

	domains := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(fileContent)))
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}

	return domains
}

// GetDataFolderPath sets data folder path
func (pm *ProxyManager) GetDataFolderPath() string {

	curDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error.")
		os.Exit(1)
	}

	return curDir + "/" + pm.DataFolder
}

// LoadCertificatePath resolve the certificate path
func (pm *ProxyManager) LoadCertificatePath() {
	pm.TLSRootCertPath = fmt.Sprintf("%s/%s-root-cert.pem", pm.GetDataFolderPath(), CertificateNamePrefix)
	pm.TLSRootKeyPath = fmt.Sprintf("%s/%s-root-key.pem", pm.GetDataFolderPath(), CertificateNamePrefix)

	pm.TLSCertPath = fmt.Sprintf("%s/cert.pem", pm.GetDataFolderPath())
	pm.TLSKeyPath = fmt.Sprintf("%s/key.pem", pm.GetDataFolderPath())

}

// CreateCertificateIfNeeded creates the certificate files
func (pm *ProxyManager) CreateCertificateIfNeeded() error {

	// Clear existing leaf certificates
	if err := DeleteFile(pm.TLSKeyPath);err != nil {
		fmt.Printf("Error in clearing existing data.")
	}

	if err := DeleteFile(pm.TLSCertPath);err != nil {
		fmt.Printf("Error in clearing existing data.")
	}

	issuer, err := minica.GetIssuer(pm.TLSRootKeyPath, pm.TLSRootCertPath)
	if err != nil {
		return err
	}

	_, err = minica.Sign(issuer, pm.GetSourceDomains(), []string{}, pm.GetDataFolderPath())
	return err
}

// UpdateHostsFile it updates the host file with the new source domains
func (pm *ProxyManager) UpdateHostsFile() error {

	sourceDomains := pm.GetSourceDomains()

	data, err := ReadHostFile()
	if err != nil {
		fmt.Printf("%v\n", err)
		return err
	}

	// delete entry of source domains if assigned to ip other than localhost ip
	for _, sourceDomain := range sourceDomains {
		for ip, domains := range data {
			index := sort.SearchStrings(domains, sourceDomain)
			if index != len(domains) {
				d := append(domains[:index], domains[index+1:]...)
				data[ip] = d
			}
		}
	}

	if _, ok := data[LocalhostIP]; !ok {
		data[LocalhostIP] = []string{}
	}

	data[LocalhostIP] = append(data[LocalhostIP], sourceDomains...)

	// @TODO remove duplicates

	if err := WriteHostFile(data); err != nil {
		fmt.Printf("%v\n", err)
		return err
	}

	return nil
}

// LoadMappings loads the proxy map
func (pm *ProxyManager) LoadMappings() error {
	if pm.Options.InputProxyFilePath != "" {
		mappings, err := pm.GetMappingsFromFile(pm.Options.InputProxyFilePath)
		if err != nil {
			log.Fatalf("Error in loading proxy file: %v", err)
			return err
		}
		pm.ProxyMap = mappings
	}

	return nil
}

// GetMappingsFromFile loads the proxy map from file
func (pm *ProxyManager) GetMappingsFromFile(filePath string) (map[string]string, error) {
	sourceToTargetMap := make(map[string]string)
	proxyFileContent, err := ReadFile(filePath)
	if err != nil {
		return sourceToTargetMap, err
	}

	// @TODO validate format here
	scanner := bufio.NewScanner(strings.NewReader(string(proxyFileContent)))
	for scanner.Scan() {
		s := scanner.Text()
		kv := strings.Split(s, ";")
		sourceToTargetMap[kv[0]] = kv[1]
	}

	return sourceToTargetMap, nil
}

func setup(pm *ProxyManager) {

	pm.SetupDataFolder()
	pm.LoadCertificatePath()

	readInputFlags(pm)

	if err := pm.LoadMappings(); err != nil {
		fmt.Println("Error in loading mappings.")
		os.Exit(1)
	}

	if err := pm.CreateCertificateIfNeeded(); err != nil {
		fmt.Println("Error in creating certificate.", err)
		os.Exit(1)
	}

	if err := pm.UpdateHostsFile(); err != nil {
		fmt.Println("Error in creating certificate.")
		os.Exit(1)
	}
}

func readInputFlags(pm *ProxyManager) {
	var proxyFile = flag.String("proxyfile", "", "Proxy file contains the list of the mappings.")
	var listCertificateDomains = flag.Bool("list-certificate-domains", false, "List all the domains which are bbind to current tls certificate.")
	var enableSSL = flag.Bool("enable-ssl", true, "Enable HTTPS")
	var certificatePath = flag.Bool("print-certificate-path", false, "Prints the path of the certificate")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
Proxy Manager supports the mapping of domains on your localhost. It runs a https
server and forwards the incoming requests based on provided mappings. e.g.
It also auto updates your hosts file. e.g. if you add following entry in proxyfile
'www.mysite.local;127.0.0.1:8080'
then it automatically adds the 'www.mysite.local' entry into the hosts file 
and forwards all the request coming on 'www.mysite.local' to '127.0.0.1:8080'

[WARN] - Proxy Manager will update your hosts file and remove all the comments which doesn't 
		contain correct ip=>domain mapping.

[INFO] - Proxy Manager will generate a new certificate everytime a new source domain is added.
		You will need to add this certificate into your system as a trusted certificate

`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) > 0 {
		fmt.Printf("More than one arguments are passed: %s.\n", flag.Args())
		os.Exit(1)
	}

	if *certificatePath == true {

		if _, err := os.Stat(pm.TLSCertPath); !os.IsNotExist(err) {
			fmt.Printf("[DIR] = %s\n", pm.GetDataFolderPath())
			fmt.Printf("[PATH] = %s\n", pm.TLSCertPath)
		} else {
			fmt.Printf("No certificate found\n")
		}

		os.Exit(0)
	}

	if *listCertificateDomains == true {
		p := pm.GetCertificateDomains()
		if len(p) > 0 {
			fmt.Println(strings.Join(p, ","))
		} else {
			fmt.Printf("No domains found.\n")
		}

		os.Exit(0)
	}

	pm.Options = ProxyManagerOptions{
		SSLEnabled:         *enableSSL,
		InputProxyFilePath: *proxyFile,
	}
}

// WriteFile writes data the file
func WriteFile(filePath string, data []byte) error {

	if _, err := os.Open(filePath); err != nil {
		return err
	}

	err := ioutil.WriteFile(filePath, data, 0644)

	return err
}

// ReadFile reads the data from file
func ReadFile(filePath string) ([]byte, error) {

	if _, err := os.Open(filePath); err != nil {
		return make([]byte, 0), err
	}

	data, err := ioutil.ReadFile(filePath)
	if err == nil {
		return data, err
	}

	return data, nil
}

// DeleteFile deletes the file if exists
func DeleteFile(filePath string) error {

	if _, err := os.Stat(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			return err
		}
	}
	
	return nil
}

// ReadHostFile reads the host and returns the result in map
func ReadHostFile() (map[string][]string, error) {

	domainResolutionMap := make(map[string][]string)

	hostFileContent, err := ReadFile(DefaultHostFilePath)
	if err != nil {
		log.Fatalf("Error reading the host file: %v", err)
		return domainResolutionMap, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(hostFileContent)))
	for scanner.Scan() {
		line := scanner.Text()
		ipRegex := regexp.MustCompile(`(#|;)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
		matches := ipRegex.FindAllString(line, 1)
		if len(matches) > 0 {
			valueStr := strings.Trim(strings.Replace(line, matches[0], "", -1), " ")
			domainResolutionMap[matches[0]] = strings.Fields(valueStr)
		}
	}

	return domainResolutionMap, nil
}

// WriteHostFile reads the host and returns the result in map
func WriteHostFile(data map[string][]string) error {

	lines := make([]string, 0)

	for k, val := range data {
		lines = append(lines, fmt.Sprintf("%s\t %s", k, strings.Join(val, " ")))
	}

	err := WriteFile(DefaultHostFilePath, []byte(strings.Join(lines, "\n")))
	if err != nil {
		log.Fatalf("Error writing the host file: %v", err)
		return err
	}

	return nil
}

