package nessus

/* TODO
do the parse. Relevant tables are :
 * the table host/problems (see ex.rb) (MOSTLY DONE)
 * the table issue/hostcount
 * TODO instead of using bullet use boolean, convert while printing
 * TODO sort table
*/

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/empijei/PTParsers"
	"github.com/moovweb/gokogiri/xml"
)

const bullet = "*"

//TODO add medium strength cipher
var simpleDefinitions = map[string]string{
	"SMTP Service STARTTLS Plaintext Command Injection":                           "STARTTLS",
	"SSL RC4 Cipher Suites Supported (Bar Mitzvah)":                               "RC4",
	"SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)":       "DHE",
	"SSL Weak Cipher Suites Supported":                                            "Weak Cipher",
	"SSL/TLS EXPORT_RSA &lt;= 512-bit Cipher Suites Supported (FREAK)":            "FREAK",
	"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)": "POODLE",
}

func Parse(inputFile string, outputFile string, severity, colSep string) (myErr error) {
	fmt.Fprintln(os.Stderr, "Opening "+inputFile)
	doc, myErr := PTParsers.ParseXML(inputFile)
	defer doc.Free()
	_ = sslIssuesTable(doc, severity, colSep)
	return
}

type row map[string]string
type service struct {
	IP   string
	FQDN string
	Port int
}

func sslIssuesTable(doc *xml.XmlDocument, severity, colSep string) (myErr error) {
	table := make(map[service]row)
	usedHeaders := make(map[string]bool)
	reportHosts, _ := doc.Search("//ReportHost")
	for i, reportHost := range reportHosts {
		reportItems, _ := reportHost.Search("ReportItem") //TODO check the err
		for j, reportItem := range reportItems {
			ip := reportHost.Attribute("name").Content()
			port, _ := strconv.Atoi(reportItem.Attribute("port").Content())
			fqdns, _ := reportHost.Search("./HostProperties/tag[@name=\"host-fqdn\"]")
			fqdn := ""
			if len(fqdns) > 0 {
				fqdn = fqdns[0].Content()
			}
			_service := service{ip, fqdn, port}
			fmt.Fprint(os.Stderr, "\rHost "+strconv.Itoa(i+1)+"/"+strconv.Itoa(len(reportHosts)))
			fmt.Fprint(os.Stderr, "	"+_service.IP+" Item "+strconv.Itoa(j+1)+"/"+strconv.Itoa(len(reportItems))+"                 ")
			if table[_service] == nil {
				table[_service] = make(row)
			}
			plugin_names, _ := reportItem.Search("plugin_name")
			plugin_name := plugin_names[0].Content()
			switch {
			case simpleDefinitions[plugin_name] != "":
				table[_service][simpleDefinitions[plugin_name]] = bullet
				usedHeaders[simpleDefinitions[plugin_name]] = true
			case plugin_name == "SSL / TLS Versions Supported":
				tmp, _ := reportItem.Search("plugin_output")
				tmpstr := tmp[0].Content()
				if strings.Contains(tmpstr, "SSLv2") {
					table[_service]["SSLv2"] = bullet
					usedHeaders["SSLv2"] = true
				}
				if strings.Contains(tmpstr, "SSLv3") {
					table[_service]["SSLv3"] = bullet
					usedHeaders["SSLv3"] = true
				}
			default:
			}
		}
	}
	fmt.Fprintln(os.Stderr, "")
	printTable(table, usedHeaders, colSep)
	return
}

func printTable(table map[service]row, usedHeaders map[string]bool, colSep string) {
	csvout := csv.NewWriter(os.Stdout)
	csvout.Comma = rune(colSep[0])
	recordlen := 3 + len(usedHeaders)
	headers := make([]string, 3, recordlen)
	headers[0] = "Host"
	headers[1] = "FQDN"
	headers[2] = "port"
	i := 0
	dynamicHeaders := make([]string, recordlen-3)
	for header, _ := range usedHeaders {
		dynamicHeaders[i] = header
		i++
	}
	sort.Strings(dynamicHeaders)
	headers = append(headers, dynamicHeaders...)
	err := csvout.Write(headers)
	if err != nil {
		fmt.Println(err.Error())
	}
	for host, problems := range table {
		if len(problems) > 0 {
			record := make([]string, recordlen)
			record[0] = host.IP
			record[1] = host.FQDN
			record[2] = strconv.Itoa(host.Port)
			for j, header := range headers[3:] {
				record[j+3] = problems[header]
			}
			_ = csvout.Write(record)
		}
	}
	csvout.Flush()
}
