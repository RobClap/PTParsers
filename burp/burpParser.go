package burp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/empijei/PTParsers"
	"github.com/moovweb/gokogiri/xml"
)

type IssueName string
type IssueNotes struct {
	IssueLocation string
	IssueNotes    string
}
type Host struct {
	IP   string
	FQDN string
}

func Parse(inputFile, outputFile string, severity, colSep string) error {
	var myErr error
	doc, myErr := PTParsers.ParseXML(inputFile)
	defer doc.Free()
	issues, _ := doc.Search("//issue")
	var issuesMap = make(map[IssueName]map[Host][]IssueNotes)
	for _, issue := range issues {
		hostNodes, _ := issue.Search("host")
		hostname := hostNodes[0].Content()
		hostIP := hostNodes[0].Attributes()["ip"].Content()
		locationNodes, _ := issue.Search("location")
		location := locationNodes[0].Content()
		nameNode, _ := issue.Search("name")
		nameContent := IssueName(nameNode[0].Content())
		if issuesMap[nameContent] == nil {
			issuesMap[nameContent] = make(map[Host][]IssueNotes)
		}
		notes := specialBehaviour(&issue, nameContent)
		issuesMap[nameContent][Host{hostIP, hostname}] = append(issuesMap[nameContent][Host{hostIP, hostname}], IssueNotes{location, notes})
	}
	for issueName, issueHosts := range issuesMap {
		fmt.Println()
		fmt.Println(string(issueName) + " [" + strconv.Itoa(len(issueHosts)) + "]")
		for issueHost, issueLocs := range issueHosts {
			fmt.Println("\t" + issueHost.FQDN) // + " (" + issueHost.IP + ")") // ") [" + strconv.Itoa(len(issueLocs)) + "]")
			for _, notes := range issueLocs {
				if tmp := string(notes.IssueLocation); tmp != "/" {
					fmt.Println("\t\t" + tmp)
				}
				if tmp := string(notes.IssueNotes); tmp != "" {
					fmt.Println("\t\t" + tmp)
				}
			}
		}
	}
	return myErr
}

func specialBehaviour(issue *xml.Node, issuename IssueName) (notes string) {
	switch issuename {
	case "Password field with autocomplete enabled":
		//<td><input type="password" name="txtPassword" id="txtPassword" maxlength="12" tabindex="2" />
		//TODO get response and search for type="password"
		responses, _ := (*issue).Search("requestresponse/response")
		response := responses[0].Content()
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if strings.Contains(line, "type=\"password\"") || strings.Contains(line, "type = \"password\"") {
				notes += line
			}
		}

	case "Cookie without HttpOnly flag set":
		//TODO prendere response e cercare Set-Cookie
		deatails, _ := (*issue).Search("issueDetailItems/issueDetailItem")
		cookiename := deatails[0].Content()
		notes += "Cookie: " + cookiename + "| "
		responses, _ := (*issue).Search("requestresponse/response")
		response := responses[0].Content()
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Set-Cookie:") {
				notes += line
			}
		}
	}
	return
}
