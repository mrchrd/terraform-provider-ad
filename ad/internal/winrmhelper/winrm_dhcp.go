package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// DHCP Reservation
type DHCPReservation struct {
	ClientID           string   `json:"ClientId"`
	ClientType         string   `json:"ClientType,ommitempty"`
	Description        string   `json:"Description,ommitempty"`
	HostName           string   `json:"HostName,ommitempty"`
	IPAddress          struct {
		IPAddress  string   `json:"IPAddressToString"`
	}                           `json:"IPAddress"`
	IPv4Address        string
	Name               string   `json:"Name,ommitempty"`
	Scope              struct {
		IPAddress  string   `json:"IPAddressToString"`
	}                           `json:"ScopeId"`
	ScopeID            string
	Type               string   `json:"Type,ommitempty"`
}

// AddDHCPReservation creates a new DHCP Reservation
func (r *DHCPReservation) AddDHCPReservation(conf *config.ProviderConf) (string, error) {
	log.Printf("[DEBUG] Adding DHCP Reservation with name %q", r.Name)
	cmds := []string{fmt.Sprintf("Add-DhcpServerv4Reservation -PassThru -ScopeId %q -IPAddress %q -ClientId %q -Name %q -Type %q", r.ScopeID, r.IPv4Address, r.ClientID, r.Name, r.Type)}

	if r.Description != "" {
		cmds = append(cmds, fmt.Sprintf("-Description %q", r.Description))
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
			return "", fmt.Errorf("there is another reservation named %q", r.Name)
		}
		return "", fmt.Errorf("command Add-DhcpServerv4Reservation exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	return r.IPv4Address, nil
}

// ModifyDHCPReservation updates an existing DHCP Reservation
func (r *DHCPReservation) ModifyDHCPReservation(d *schema.ResourceData, conf *config.ProviderConf) error {
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

// DeleteDHCPReservation removes a DHCP Reservation
func (r *DHCPReservation) DeleteDHCPReservation(conf *config.ProviderConf) error {
	cmd := fmt.Sprintf("Remove-DhcpServerv4Reservation -IPAddress %q", r.IPv4Address)
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
		return fmt.Errorf("while removing dhcp reservation: stderr: %s", result.StdErr)
	}
	return nil
}

// GetDHCPReservationFromResource returns a DHCP Reservation struct built from Resource data
func GetDHCPReservationFromResource(d *schema.ResourceData) *DHCPReservation {
	r := DHCPReservation{
		ClientID:          SanitiseTFInput(d, "client_id"),
		Description:       SanitiseTFInput(d, "description"),
		IPv4Address:       SanitiseTFInput(d, "ipv4_address"),
		Name:              SanitiseTFInput(d, "name"),
		ScopeID:           SanitiseTFInput(d, "scope_id"),
		Type:              SanitiseTFInput(d, "type"),
	}

	return &r
}

// GetDHCPReservationFromHost returns a DHCP Reservation struct based on data
// retrieved from the DHCP Server.
func GetDHCPReservationFromHost(conf *config.ProviderConf, id string) (*DHCPReservation, error) {
	cmd := fmt.Sprintf("Get-DhcpServerv4Reservation -IPAddress %q", id)
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
		return nil, fmt.Errorf("command Get-DhcpServerv4Reservation exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	r, err := unmarshallDHCPReservation([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling dhcp reservation json document: %s", err)
	}

	return r, nil
}

// GetDHCPLeaseFromHost returns a DHCP Lease struct based on data
// retrieved from the DHCP Server.
func GetDHCPLeaseFromHost(conf *config.ProviderConf, id string) (*DHCPReservation, error) {
        cmd := fmt.Sprintf("Get-DhcpServerv4Lease -IPAddress %q", id)
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
                return nil, fmt.Errorf("command Get-DhcpServerv4Lease exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
        }

        r, err := unmarshallDHCPReservation([]byte(result.Stdout))
        if err != nil {
                return nil, fmt.Errorf("error while unmarshalling dhcp lease json document: %s", err)
        }

        return r, nil
}

// unmarshallDHCPReservation unmarshalls the incoming byte array containing JSON
// into a DHCPReservation structure and populates all fields based on the data
// extracted.
func unmarshallDHCPReservation(input []byte) (*DHCPReservation, error) {
	var r DHCPReservation
	err := json.Unmarshal(input, &r)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}

	if r.HostName != "" {
		r.Name = string(r.HostName)
		r.Type = string(r.ClientType)
	}

	if r.Name == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling DHCP Reservation data, json doc was: %s", string(input))
	}

	r.IPv4Address = string(r.IPAddress.IPAddress)
	r.ScopeID = string(r.Scope.IPAddress)

	return &r, nil
}
