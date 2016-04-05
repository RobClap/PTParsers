package burp

import (
	"fmt"
	"strconv"

	"github.com/RobClap/PTParsers"
)

type IssueName string
type IssueLocation string
type Host struct {
	IP   string
	FQDN string
}

func Parse(inputFile, outputFile string, severity, colSep string) error {
	var myErr error
	doc, myErr := PTParsers.ParseXML(inputFile)
	defer doc.Free()
	issues, _ := doc.Search("//issue")
	var issuesMap = make(map[IssueName]map[Host][]IssueLocation)
	for _, issue := range issues {
		hostNodes, _ := issue.Search("host")
		hostname := hostNodes[0].Content()
		hostIP := hostNodes[0].Attributes()["ip"].Content()
		locationNodes, _ := issue.Search("location")
		location := IssueLocation(locationNodes[0].Content())
		nameNode, _ := issue.Search("name")
		nameContent := IssueName(nameNode[0].Content())
		if issuesMap[nameContent] == nil {
			issuesMap[nameContent] = make(map[Host][]IssueLocation)
		}
		issuesMap[nameContent][Host{hostIP, hostname}] = append(issuesMap[nameContent][Host{hostIP, hostname}], location)
	}
	for issueName, issueHosts := range issuesMap {
		fmt.Println()
		fmt.Println(string(issueName) + " [" + strconv.Itoa(len(issueHosts)) + "]")
		for issueHost, issueLocs := range issueHosts {
			fmt.Println("\t" + issueHost.FQDN + " (" + issueHost.IP + ") [" + strconv.Itoa(len(issueLocs)) + "]")
			for _, issueLoc := range issueLocs {
				if tmp := string(issueLoc); issueLoc != "/" {
					fmt.Println("\t\t" + tmp)
				}
			}
		}
	}
	return myErr
}
