package nessus

/* TODO
do the parse. Relevant tables are :
 * the table host/problems (see ex.rb)
 * the table issue/hostcount
 * the full csv translation (see simple-nessus)
*/

import (
	"fmt"

	"github.com/RobClap/PTParsers"
	"github.com/moovweb/gokogiri/xml"
)

var simpleDefinitions = map[string]string{
	"SSL RC4 Cipher Suites Supported (Bar Mitzvah)":                               "RC4",
	"SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)":       "DHE",
	"SSL Weak Cipher Suites Supported":                                            "Weak Cipher",
	"SSL/TLS EXPORT_RSA &lt;= 512-bit Cipher Suites Supported (FREAK)":            "FREAK",
	"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)": "POODLE",
}

func Parse(inputFile string, outputFile string, severity, colSep string) (myErr error) {
	doc, myErr := PTParsers.ParseXML(inputFile)
	defer doc.Free()
	_ = sslIssuesTable(doc, severity, colSep)
	return
}

type row map[string]string
type service struct {
	IP   string
	Port int
}

func sslIssuesTable(doc *xml.XmlDocument, severity, colSep string) (myErr error) {
	table := make(map[service]row)
	reportHosts, _ := doc.Search("//ReportHost")
	for _, reportHost := range reportHosts {
		reportItems, _ := reportHost.Search("//ReportItem") //TODO check the err
		for _, reportItem := range reportItems {
			tmp, _ := reportHost.Search("//name")
			ip := service{(tmp[0].Content()), 0} //TODO parse port!
			if table[ip] == nil {
				table[ip] = make(row)
			}
			plugin_names, _ := reportItem.Search("plugin_name")
			plugin_name := plugin_names[0].Content()
			switch {
			case simpleDefinitions[plugin_name] != "":
				table[ip][simpleDefinitions[plugin_name]] = "*"
			case plugin_name == "SSL / TLS Versions Supported":
				fmt.Println("TODO detect SSl version")
			default:
			}
		}
	}

	return
}
