package main

import (
  "os"
  "fmt"
  "net"
  "log"
  "bufio"
  "strings"
  "encoding/csv"
  "github.com/domainr/whois"
  "github.com/skratchdot/open-golang/open"
)


/**
 * CONFIG STUFF
 */
var hotList = []string{
	"paypal",
	"apple",
	"amazon",
	"login",
	"secure",
}

// Extend this if there is more data you want to record (Like HTML etc)
type suspiciousDomain struct {
    name   string
    ips   []string
    dns   []string
    whois  string
}

/**
 * END OF CONFIG STUFF
 */

var checkList = make(map[int]string)

var profiles = make(map[string]suspiciousDomain)


func isSuspicious(d string) bool {
	d = strings.ToLower(d)
	for _, h := range hotList {
		if strings.Contains(d, h) {
			return true
		}
	}
	return false
}

/**
 *  https://gist.github.com/m4ng0squ4sh/3dcbb0c8f6cfe9c66ab8008f55f8f28b
 */
func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}

func buildCSV(profiles map[string]suspiciousDomain, fileName string) {
	records := [][]string{
		{"processed", "domain", "ips", "dns", "whois"},
	}
	for _, v := range profiles {
		s := []string{
			"",
			v.name,
			strings.Join(v.ips, " "),
			strings.Join(v.dns, " "),
			v.whois,
		}
		records = append(records, s)
	}
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
    defer file.Close()
	w := csv.NewWriter(file)

	for _, record := range records {
		if err := w.Write(record); err != nil {
			log.Fatalln("error writing record to csv:", err)
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Wrote %d records to %s\n", len(profiles), fileName)
}

func processDomain(k int, v string, checkList map[int]string) map[int]string {
	fmt.Printf("Grabbing %s ip, dns, and whois\n", v)
 	ips, err := net.LookupHost(v)
	if err != nil {
		fmt.Println("[!]", err)
		delete(checkList, k)
		return checkList
	}
	ns, _ := net.LookupNS(v)
	dns := []string{}
	for _, n := range ns {
		dns = append(dns, n.Host)
	}
	wRequest, err := whois.NewRequest(v)
	if err != nil {
		log.Fatal(err)
	}
	wResponse, err := whois.DefaultClient.Fetch(wRequest)
	if err != nil {
		log.Fatal(err)
	}
   	profiles[v] = suspiciousDomain{
	    name: v,
	    ips: ips,
	    dns:  dns,
	    whois: string(wResponse.Body),
	}
	if askForConfirmation("Open " + v + " in browser?") {
    	open.Run("http://" + v)
    	if !askForConfirmation("Keep " + v + " in list?") {
    		delete(checkList, k)
    	}
    }
    return checkList
}

func loadDomains(inputFileName string) {
    file, _ := os.Open(inputFileName)
    defer file.Close()
    s := bufio.NewScanner(file)
	s.Split(bufio.ScanLines) 
    for s.Scan() {
    	if isSuspicious(s.Text()) {
			checkList[len(checkList) - 1] = s.Text()
		}
    }
}

func main() {
	if len(os.Args) < 3 {
    	fmt.Printf("Usage: %s input.txt out.csv\n", os.Args[0])
    	return
	}

	inputFileName  := os.Args[1]
	csvFileName := os.Args[2]

	loadDomains(inputFileName)

    c := len(checkList)
    fmt.Printf("Found %d suspicious domains\n", c)
    fmt.Println("Iterating through suspicious items...")

    for k, v := range checkList {
    	if !askForConfirmation("Keep " + v) {
    	// This is just for testing
    	//if k > 4 || v == "" {
    		delete(checkList, k)
		}
    }
    c = len(checkList)
    fmt.Printf("Analysing %d domain(s)...\n", c)
    fmt.Println("Starting manual site inspection...")
    for k, v := range checkList {
    	checkList = processDomain(k, v, checkList)
    }
    c = len(checkList)
    fmt.Printf("Exporting %d bad domains to CSV...\n", c)
    buildCSV(profiles, csvFileName)
}