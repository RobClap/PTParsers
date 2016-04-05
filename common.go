package PTParsers

import (
	"io/ioutil"

	"github.com/moovweb/gokogiri"
	"github.com/moovweb/gokogiri/xml"
)

func ParseXML(inputFile string) (*xml.XmlDocument, error) {
	var err error
	var doc *xml.XmlDocument
	xmlContent, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return doc, err
	}
	doc, err = gokogiri.ParseXml(xmlContent)
	if err != nil {
		return doc, err
	}
	return doc, err
}
