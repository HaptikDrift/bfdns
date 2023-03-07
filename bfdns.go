/*
	The following project is a proof of concept:
	Project Title: bfdns
	Goal or Aim:
	* To enumerate DNS entries
	* Make DNS query on possible name combinations
	* Print any findings
	* Have the possibility to lookup the geo-loaction of IP addresses (IPv4 or v6)
	ToDo:
	- Save to or write to local database or online option
	- Save output to file
	- possibly use a format, such as JSON
	- Write-out to an easy to "report" format (possible csv or tsv)
	written by Haptik Drift
	<haptikdrift@gmail.com>
*/
package main

/* All imports needed in the main function */
import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dariubs/percent"
	"github.com/schollz/progressbar/v3"
)

// Declare Wait Groups
var wg sync.WaitGroup
var jwg sync.WaitGroup

/* Apply a visuale system of version */
const version = "0.1"

/* MAIN FUNCTION */
func main() {
	// Declare flag variables
	var (
		prefixPtr, domainPtr, suffixPtr, startbanner, shodanKeyPtr string
		threadsPtr                                                 int
	)
	startbanner = `[+] ... DNS BruteForce Starting ...`

	// Present operation flags or operation syntax
	// Perfix - setup
	flag.StringVar(&prefixPtr, "prefix", "dns-prefixes.txt", "this is for the prefix of a domain.")
	flag.StringVar(&prefixPtr, "p", "dns-prefixes.txt", "this is for the prefix of a domain (-prefix).")
	// Domain - setup
	flag.StringVar(&domainPtr, "domain", "", "this is for the hostname of a domain (without the suffix).")
	flag.StringVar(&domainPtr, "d", "", "this is for the hostname of a domain (-domain) (without the suffix).")
	// Suffix - setup
	flag.StringVar(&suffixPtr, "suffix", "dns-suffix.txt", "this is for the suffix of a domain.")
	flag.StringVar(&suffixPtr, "s", "dns-suffix.txt", "this is for the suffix of a domain (-suffix).")
	// Optional Flags
	flag.StringVar(&shodanKeyPtr, "shokey", "", "API for intercation with Shodan online API.")
	flag.IntVar(&threadsPtr, "t", 10, "Number of concurrent threads (the default is 10 if this flag is not applied.)")
	geoPtr := flag.Bool("geo", false, "Run geo-loocation resolution on IP addresses resolved in DNS searches or\n\t\t   querry. Geo-location infomation is gathered from an online API and is\n\t\t   rate limited to one request every 2 seconds.")
	shodanDomainPtr := flag.Bool("shodom", false, "Run second level domain infomation search against Shodan online API.\n\t\t   Please note a Shodan API key will be required for this option.")
	// Parse all the flags
	flag.Usage = func() {
		flagSet := flag.CommandLine
		shorthand := []string{"p", "d", "s"}
		fmt.Printf("\n    	The following syntax is for shorthand operational flags:\n\n")
		for _, name := range shorthand {
			flag := flagSet.Lookup(name)
			fmt.Printf("\t-%s\t | %s\n", flag.Name, flag.Usage)
		}
		longhand := []string{"prefix", "domain", "suffix"}
		fmt.Printf("\n    	The following syntax is for longhand operational flags:\n\n")
		for _, name := range longhand {
			flag := flagSet.Lookup(name)
			fmt.Printf("\t-%s\t | %s\n", flag.Name, flag.Usage)
		}
		optional := []string{"t", "geo", "shokey", "shodom"}
		fmt.Printf("\n    	The following syntax is for optional operational flags:\n\n")
		for _, name := range optional {
			flag := flagSet.Lookup(name)
			fmt.Printf("\t-%s\t | %s\n", flag.Name, flag.Usage)
		}
		fmt.Printf("\n    	The following shows examples of tool usage:\n\n")
		fmt.Printf("    	./bfdns -p dns-prefixes.txt -domain google -s dns-suffixes.txt\n")
		fmt.Printf("    	./bfdns -p dns-prefixes.txt -d google -s dns-suffixes.txt -t 100\n")
		fmt.Printf("    	./bfdns -prefix dns-prefixes.txt -domain google -suffix dns-suffixes.txt -t 30 -geo\n")
		fmt.Printf("\n\n")
	}
	flag.Parse()

	// If no file presented to the application, print the banner message
	if (prefixPtr == "") || (domainPtr == "") || (suffixPtr == "") {
		flagbanner()
		flag.Usage()
		return
	}

	// If no API presented to the application, print the banner message
	if *shodanDomainPtr && (shodanKeyPtr == "") {
		flagbanner()
		flag.Usage()
		return
	}
	// Craete two channels, see worker() function below.
	jobs := make(chan string, 100)
	results := make(chan string, 100)
	// Setup jobs
	for i := 0; i < threadsPtr; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(jobs, results)
		}()
	}
	// Reading from Channel in Go-Routine
	jwg.Add(1)

	var collection []DomIP

	// Variable assignment from command line(flag) input
	dom := domainPtr
	strPrefix, _ := FileToSlice(prefixPtr)
	strSuffix, _ := FileToSlice(suffixPtr)

	var x, y int
	x = len(strPrefix)
	y = len(strSuffix)
	s := x * y
	fmt.Println(startbanner)
	fmt.Printf("\n[+] ... Resolution of %d possible hostnames starting \n\n", s)
	n := int64(s)
	bar := progressbar.Default(n)

	/// Set GO Routine print out stacked results
	go func() {
		defer jwg.Done()
		for in := range results {
			//fmt.Println(in)
			split := strings.Split(in, " = ")
			a := DomIP{
				Dom: split[0],
				Ip:  split[1],
			}
			collection = append(collection, a)
		}
	}()

	var twg sync.WaitGroup

	// Main Loop for stacking Jobs and stacking the Results
	for _, suff := range strSuffix {
		for _, pre := range strPrefix {
			twg.Add(1)
			go func(pre string, dom string, suff string) {
				defer twg.Done()
				Domain := fmt.Sprintf("%s.%s.%s", pre, dom, suff)
				ips, _ := net.LookupIP(Domain)
				bar.Add(1)
				if len(ips) > 0 {
					for _, ip := range ips {
						resolve := fmt.Sprintf("%s = %s", Domain, ip.String())
						// Send data to go-routine
						jobs <- resolve
					}
				}
			}(pre, dom, suff)
		}
	}

	twg.Wait()

	// Close the channel (jobs)
	close(jobs)

	// Add Wait Group
	wg.Add(1)
	go func() {
		defer wg.Done()
		jwg.Wait()
	}()

	// Close the channel (resluts)
	close(results)

	// Close the wait groups
	wg.Wait()

	// Sort the output by domain
	sort.Sort(ByDom(collection))
	for _, i := range collection {
		fmt.Println(i.Dom + " = " + i.Ip)
	}
	found := len(collection)
	fmt.Printf("\n[+] ... DNS resolution completed %d/%d entries found!\n", found, s)
	//var percentage float64
	percentage := percent.PercentOfFloat(float64(found), float64(s))
	fmt.Printf("[+] ... %2.2f %% Of generated DNS names were found to resolve to IP addresses\n\n", percentage)

	// The following will run if -geo flag is used
	if *geoPtr {
		fmt.Printf("[+] ... Checking the geo-location of IP addresses found\n\n")
		for _, i := range collection {
			time.Sleep(2 * time.Second)
			data := GeolocationIP{}
			_ = json.Unmarshal(GeoIPCheck(i.Ip), &data)
			if data.Status == "success" {
				fmt.Println("Hostname:                        ", i.Dom)
				fmt.Println("IP Address Querried (IP):        ", data.Query)
				fmt.Println("Autonomous System Number (ASN):  ", data.As)
				fmt.Println("Internet Service Provider (ISP): ", data.Isp)
				fmt.Println("Geo-Location - Latitude (LAT):   ", data.Lat)
				fmt.Println("Geo-Location - Longatude (LON):  ", data.Lon)
				fmt.Println("\nOrganisation (ORG):       ", data.Org)
				fmt.Println("City (CITY):              ", data.City)
				fmt.Println("State:                    ", data.RegionName)
				fmt.Println("Country:                  ", data.Country)
				fmt.Println("State Code Aberviation :  ", data.Region)
				fmt.Println("Country Code Aberviation: ", data.CountryCode)
				fmt.Printf("\n")
			}
		}
		fmt.Printf("[+] ... Geo-location checks complete\n\n")
	}

	if *shodanDomainPtr && (len(shodanKeyPtr) > 0) {
		fmt.Printf("[+] ... Checking SLD/2LD(s) on Shodan possible subdomain information\n\n")
		for _, i := range strSuffix {
			dom := domainPtr
			Domain := fmt.Sprintf("%s.%s", dom, i)
			time.Sleep(2 * time.Second)
			data := ShodanDomainInfo{}
			_ = json.Unmarshal(ShodanDomainInfoCheck(Domain, shodanKeyPtr), &data)
			strPrefix = append(strPrefix, data.Subdomains...)
			fmt.Printf("\n")
		}
		fmt.Printf("[+] ... Shodan SLD/2LD(s) checks complete\n\n")
	}
}

/* Functions used inside the main loop */

// Raise software banner includeing version
func flagbanner() {
	fmt.Printf("\n\tBrute Force DNS (bfdns) - version = %s", version) // Pull version const
	fmt.Printf("\n\t---------------------------------------------------\n\tThis is a DNS or hostname resolution, brute-forcing\n\ttool that supports geo-location and threading\n\t---------------------------------------------------\n")
}

// Create job channels to handle DNS Queries and stack the Results
func worker(jobs <-chan string, results chan<- string) {
	for jobin := range jobs {
		results <- jobin
	}
}

// Convert a text file ('.txt') in a slice for easy interation
func FileToSlice(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		lines = append(lines, scan.Text())
	}
	return lines, scan.Err()
}

// Function to check geo-location
func GeoIPCheck(v string) []byte {
	Header := map[string][]string{
		"Host":            {"ip-api.com"},
		"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
		"Accept-Language": {"en-GB,en;q=0.5"},
		"Content-Type":    {"application/x-www-form-urlencoded"},
		"Content-Length":  {"0"},
		"Origin":          {"http://ip-api.com/"},
	}

	url := "http://ip-api.com/json/" + v

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header = Header
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return bodyBytes
}

// Geo-location struct to populate info for geo website
type GeolocationIP struct {
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Isp         string  `json:"isp"`
	Org         string  `json:"org"`
	As          string  `json:"as"`
}

// Function to check Shodan Domain info
func ShodanDomainInfoCheck(v string, shodanKeyPtr string) []byte {
	Header := map[string][]string{
		"Host":            {"api.shodan.io"},
		"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
		"Accept-Language": {"en-GB,en;q=0.5"},
		"Content-Type":    {"application/x-www-form-urlencoded"},
		"Content-Length":  {"0"},
		"Origin":          {"https://api.shodan.io/"},
	}

	url := "https://api.shodan.io/dns/domain/" + v + "?key=" + shodanKeyPtr

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header = Header
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return bodyBytes
}

// Shodan struct to populate info from Shoadan website
type ShodanDomainInfo struct {
	More   bool          `json:"more"`
	Domain string        `json:"domain"`
	Tags   []interface{} `json:"tags"`
	Data   []struct {
		Tags      []string  `json:"tags,omitempty"`
		Subdomain string    `json:"subdomain"`
		Type      string    `json:"type"`
		Ports     []int     `json:"ports,omitempty"`
		Value     string    `json:"value"`
		LastSeen  time.Time `json:"last_seen"`
	} `json:"data"`
	Subdomains []string `json:"subdomains"`
}

// For Resolved IP addresses to be placed into collection slice to be sorted
type DomIP struct {
	Dom string
	Ip  string
}

// For sorting by IP
type ByIP []DomIP

func (a ByIP) Len() int {
	return len(a)
}

func (a ByIP) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByIP) Less(i, j int) bool {
	return a[i].Ip < a[j].Ip
}

// For sorting by Domain
type ByDom []DomIP

func (a ByDom) Len() int {
	return len(a)
}

func (a ByDom) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ByDom) Less(i, j int) bool {
	return a[i].Dom < a[j].Dom
}
