package burp

import (
	"fmt"
	"strconv"

	"github.com/RobClap/PTParsers"
)

type IssueName string
type Host struct {
	IP   string
	FQDN string
}

func Parse(inputFile, outputFile string, severity, colSep string) error {
	var myErr error
	doc, myErr := PTParsers.ParseXML(inputFile)
	defer doc.Free()
	issues, _ := doc.Search("//issue")
	var issuesMap = make(map[IssueName][]Host) //TODO use a map for hosts, count issues by host
	for _, issue := range issues {
		hostNode, _ := issue.Search("host")
		hostname := hostNode[0].Content()
		nameNode, _ := issue.Search("name")
		nameContent := IssueName(nameNode[0].Content())
		issuesMap[nameContent] = append(issuesMap[nameContent], Host{"", hostname})
	}
	for issueName, issueHosts := range issuesMap {
		fmt.Println(string(issueName) + " " + strconv.Itoa(len(issueHosts)))
	}
	return myErr
}
