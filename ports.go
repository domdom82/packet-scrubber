package main

import (
	"encoding/csv"
	"fmt"
	"github.com/google/gopacket/layers"
	"os"
	"regexp"
	"strconv"
)

type ianaEntry struct {
	ServiceName             string
	PortNumber              layers.TCPPort
	TransportProtocol       string
	Description             string
	Assignee                string
	Contact                 string
	RegistrationDate        string
	ModificationDate        string
	Reference               string
	ServiceCode             string
	UnauthorizedUseReported string
	AssignmentNotes         string
}

type IanaDB struct {
	registeredPorts map[layers.TCPPort]*ianaEntry
}

func NewIanaDB(csvFile string) (*IanaDB, error) {
	db := &IanaDB{map[layers.TCPPort]*ianaEntry{}}

	f, err := os.Open(csvFile)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	for l, line := range data {
		if l > 0 { // omit header line
			var rec ianaEntry
			var low, high int
			for f, field := range line {
				switch f {
				case 0:
					rec.ServiceName = field
				case 1:
					port, err := strconv.Atoi(field)
					if err != nil {
						low, high, err = getPortRange(field)
						if err != nil {
							// if it has no port and no port range it can't be a reserved port, so skip it
							continue
						}
					} else {
						rec.PortNumber = layers.TCPPort(port)
					}
				case 2:
					rec.TransportProtocol = field
				case 3:
					rec.Description = field
				case 4:
					rec.Assignee = field
				case 5:
					rec.Contact = field
				case 6:
					rec.RegistrationDate = field
				case 7:
					rec.ModificationDate = field
				case 8:
					rec.Reference = field
				case 9:
					rec.ServiceCode = field
				case 10:
					rec.UnauthorizedUseReported = field
				case 11:
					rec.AssignmentNotes = field
				}
			}
			if low != 0 && high != 0 {
				for portNumber := low; portNumber <= high; portNumber++ {
					db.registeredPorts[layers.TCPPort(portNumber)] = &rec
				}
			} else {
				db.registeredPorts[rec.PortNumber] = &rec
			}
		}
	}
	return db, nil
}

// getPortRange returns a possible low and high port range from strings like "100-200"
func getPortRange(field string) (low, high int, err error) {
	var regex = regexp.MustCompile("(?P<low>\\d)-(?P<high>\\d)")
	match := regex.FindStringSubmatch(field)

	paramsMap := make(map[string]string)
	for i, name := range regex.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}

	if paramsMap["low"] == "" || paramsMap["high"] == "" {
		return 0, 0, fmt.Errorf("could not find a low and high range value in port field '%s'", field)
	}

	low, err = strconv.Atoi(paramsMap["low"])
	if err != nil {
		return 0, 0, err
	}

	high, err = strconv.Atoi(paramsMap["high"])
	if err != nil {
		return 0, 0, err
	}

	return low, high, nil
}

// isPortEphemeral returns true if the port
// 1. is not well-known
// 2. is not a registered port as per IANA assignment
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
func (db *IanaDB) isPortEphemeral(port layers.TCPPort) bool {
	if port <= 1024 {
		return false
	}
	if db.registeredPorts[port] != nil {
		return false
	}
	return true
}
