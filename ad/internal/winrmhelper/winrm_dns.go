package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Cim Instance Property
type CIProperty struct {
	Name  string          `json:"Name"`
	Value json.RawMessage `json:"Value,ommitempty"`
}

// DNS Record
type DNSRecord struct {
	DistinguishedName string `json:"DistinguishedName"`
	IPv4Address       string
	Name              string `json:"HostName"`
	Data              struct {
		CimInstanceProperties []CIProperty `json:"CimInstanceProperties"`
	} `json:"RecordData"`
	Type       string `json:"RecordType"`
	TimeToLive struct {
		TotalSeconds float64 `json:"TotalSeconds"`
	} `json:"TimeToLive"`
	TTL      int
	ZoneName string
}

// AddDNSRecord creates a new DNS Record
func (r *DNSRecord) AddDNSRecord(conf *config.ProviderConf) (string, error) {
	log.Printf("[DEBUG] Adding DNS Record with name %q", r.Name)
	cmds := []string{fmt.Sprintf("Add-DnsServerResourceRecord -AllowUpdateAny -ZoneName %q -Name %q", r.ZoneName, r.Name)}

	switch r.Type {
	case "A":
		cmds = append(cmds, fmt.Sprintf("-A -IPv4Address %q", r.IPv4Address))
	}

	if r.TTL >= 0 {
		cmds = append(cmds, fmt.Sprintf("-TimeToLive $([System.TimeSpan]::FromSeconds(%d))", r.TTL))
	}

	psOpts := CreatePSCommandOpts{
		JSONOutput:      true,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand(cmds, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		return "", err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		if strings.Contains(result.StdErr, "ResourceExists") {
			return "", fmt.Errorf("there is another record named %q", r.Name)
		}
		return "", fmt.Errorf("command Add-DnsServerResourceRecord exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	// Generate an ID
	vars := []string{
		r.ZoneName,
		r.Name,
		r.Type,
	}
	id := strings.Join(vars, "_")

	return id, nil
}

// ModifyDNSRecord updates an existing DNS Record
func (r *DNSRecord) ModifyDNSRecord(d *schema.ResourceData, conf *config.ProviderConf) error {
	/*
		KeyMap := map[string]string{
			"sam_account_name": "SamAccountName",
			"scope":            "GroupScope",
			"category":         "GroupCategory",
			"description":      "Description",
		}

		cmds := []string{fmt.Sprintf("Set-ADGroup -Identity %q", g.GUID)}

		for k, param := range KeyMap {
			if d.HasChange(k) {
				value := SanitiseTFInput(d, k)
				if value == "" {
					value = "$null"
				} else {
					value = fmt.Sprintf(`"%s"`, value)
				}
				cmds = append(cmds, fmt.Sprintf(`-%s %s`, param, value))
			}
		}

		if len(cmds) > 1 {
			psOpts := CreatePSCommandOpts{
				JSONOutput:      true,
				ForceArray:      false,
				ExecLocally:     conf.IsConnectionTypeLocal(),
				PassCredentials: conf.IsPassCredentialsEnabled(),
				Username:        conf.Settings.WinRMUsername,
				Password:        conf.Settings.WinRMPassword,
				Server:          conf.IdentifyDomainController(),
			}
			psCmd := NewPSCommand(cmds, psOpts)
			result, err := psCmd.Run(conf)
			if err != nil {
				return err
			}
			if result.ExitCode != 0 {
				log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
				return fmt.Errorf("command Set-ADGroup exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
			}
		}

		if d.HasChange("name") {
			cmd := fmt.Sprintf("Rename-ADObject -Identity %q -NewName %q", g.GUID, d.Get("name").(string))
			psOpts := CreatePSCommandOpts{
				JSONOutput:      true,
				ForceArray:      false,
				ExecLocally:     conf.IsConnectionTypeLocal(),
				PassCredentials: conf.IsPassCredentialsEnabled(),
				Username:        conf.Settings.WinRMUsername,
				Password:        conf.Settings.WinRMPassword,
				Server:          conf.IdentifyDomainController(),
			}
			psCmd := NewPSCommand([]string{cmd}, psOpts)
			result, err := psCmd.Run(conf)
			if err != nil {
				return err
			}
			if result.ExitCode != 0 {
				log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
				return fmt.Errorf("command Rename-ADObject exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
			}
		}

		if d.HasChange("container") {
			cmd := fmt.Sprintf("Move-ADObject -Identity %q -TargetPath %q", g.GUID, d.Get("container").(string))
			psOpts := CreatePSCommandOpts{
				JSONOutput:      true,
				ForceArray:      false,
				ExecLocally:     conf.IsConnectionTypeLocal(),
				PassCredentials: conf.IsPassCredentialsEnabled(),
				Username:        conf.Settings.WinRMUsername,
				Password:        conf.Settings.WinRMPassword,
				Server:          conf.IdentifyDomainController(),
			}
			psCmd := NewPSCommand([]string{cmd}, psOpts)
			result, err := psCmd.Run(conf)
			if err != nil {
				return fmt.Errorf("winrm execution failure while moving group object: %s", err)
			}
			if result.ExitCode != 0 {
				return fmt.Errorf("Move-ADObject exited with a non zero exit code (%d), stderr: %s", result.ExitCode, result.StdErr)
			}
		}

	*/
	return nil
}

// DeleteDNSRecord removes a DNS Record
func (r *DNSRecord) DeleteDNSRecord(conf *config.ProviderConf) error {
	cmd := fmt.Sprintf("Remove-DnsServerResourceRecord -Force -ZoneName %q -Name %q -RRType %q", r.ZoneName, r.Name, r.Type)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      true,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand([]string{cmd}, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		// Check if the resource is already deleted
		if strings.Contains(err.Error(), "ObjectNotFound") {
			return nil
		}
		return err
	} else if result.ExitCode != 0 {
		return fmt.Errorf("while removing dns record: stderr: %s", result.StdErr)
	}
	return nil
}

// GetDNSRecordFromResource returns a DNS Record struct built from Resource data
func GetDNSRecordFromResource(d *schema.ResourceData) *DNSRecord {
	r := DNSRecord{
		DistinguishedName: SanitiseString(d.Get("dn").(string)),
		IPv4Address:       SanitiseTFInput(d, "ipv4_address"),
		Name:              SanitiseTFInput(d, "name"),
		TTL:               d.Get("ttl").(int),
		Type:              SanitiseTFInput(d, "type"),
		ZoneName:          SanitiseTFInput(d, "zone"),
	}

	return &r
}

// GetDNSRecordFromHost returns a DNS Record struct based on data
// retrieved from the DNS Server.
func GetDNSRecordFromHost(conf *config.ProviderConf, id string) (*DNSRecord, error) {
	parts := ParseDNSRecordID(id)
	zone := parts[0]
	name := parts[1]
	rrtype := parts[2]
	cmd := fmt.Sprintf("Get-DnsServerResourceRecord -Node -ZoneName %q -Name %q -RRType %q", zone, name, rrtype)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      true,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand([]string{cmd}, psOpts)
	result, err := psCmd.Run(conf)

	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return nil, fmt.Errorf("command Get-DnsServerResourceRecord exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	r, err := unmarshallDNSRecord([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling dns record json document: %s", err)
	}

	return r, nil
}

func ParseDNSRecordID(id string) [3]string {
	var zone, name, rrtype string
	parts := strings.Split(id, "_")
	if len(parts) > 1 {
		zone = parts[0]
	}
	if len(parts) >= 3 {
		var typeIndex int = -1
		for i, maybeType := range parts[1:] {
			if maybeType == "A" {
				typeIndex = i + 1
				break
			}
		}
		if typeIndex > 1 {
			name = strings.Join(parts[1:typeIndex], "_")
			name = strings.TrimSuffix(name, ".")
			rrtype = parts[typeIndex]
		}
	}
	return [3]string{zone, name, rrtype}
}

// unmarshallDNSRecord unmarshalls the incoming byte array containing JSON
// into a DNSRecord structure and populates all fields based on the data
// extracted.
func unmarshallDNSRecord(input []byte) (*DNSRecord, error) {
	var r DNSRecord
	err := json.Unmarshal(input, &r)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}
	if r.Name == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling DNS Record data, json doc was: %s", string(input))
	}

	for _, p := range r.Data.CimInstanceProperties {
		if p.Name == "IPv4Address" {
			err := json.Unmarshal(p.Value, &r.IPv4Address)
			if err != nil {
				return nil, fmt.Errorf("could not unmarshal string value=%q: %w", p.Value, err)
			}
		}
	}

	r.TTL = int(r.TimeToLive.TotalSeconds)

	dnParts := strings.Split(r.DistinguishedName, ",")
	r.ZoneName = strings.TrimPrefix(dnParts[1], "DC=")

	return &r, nil
}
