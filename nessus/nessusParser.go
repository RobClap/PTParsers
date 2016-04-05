package goNessusParser

import (
	"fmt"

	"github.com/RobClap/PTParsers"
)

func Parse(inputFile string, outputFile string, severity, colSep string) error {
	var myErr error
	doc, myErr := PTParsers.ParseXML(inputFile)
	defer doc.Free()
	reportItems, _ := doc.Search("//ReportItem") //TODO check the err
	for _, reportItem := range reportItems {
		/*do the parse. Relevant tables are :
		 * the table host/problems (see ex.rb)
		 * the table issue/hostcount
		 */
		fmt.Println(reportItem.Content())
	}
	return myErr
}
