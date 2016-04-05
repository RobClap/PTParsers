package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RobClap/PTParsers/burp"
)

var serve = flag.Bool("serve", false, "If specified runs in server mode")
var port = flag.Int("port", 8835, "The port to use in server mode, in normal mode it is ignored")
var file = flag.String("file", "", "The nessus file to process")
var severity = flag.String("severity", "L", "Minimum Severity Level: [A]ll, [L]ow, [M]edium, [H]igh, [C]ritical")
var sep = flag.String("colSep", ";", "Minimum Severity Level: [A]ll, [L]ow, [M]edium, [H]igh, [C]ritical")

func main() {
	flag.Parse()
	if !*serve {
		/*		inputReader, errRead := os.Open(*file)
				errCheck(errRead)
				outputWriter, errWrite := os.OpenFile(*file+".csv", os.O_WRONLY, 0666)
				errCheck(errWrite)
				errParse := goNessusParser.Parse(inputReader, outputWriter, *severity, *sep)
		*/
		errParse := burp.Parse(*file, *file+".csv", *severity, *sep)
		errCheck(errParse)
	}
}

func errCheck(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err.Error())
		os.Exit(1)
	}
}
