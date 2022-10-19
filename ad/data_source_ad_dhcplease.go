package ad

import (
	"fmt"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func dataSourceDHCPLease() *schema.Resource {
	return &schema.Resource{
		Description: "Get the details of a DHCP Lease.",
		Read:        dataSourceDHCPLeaseRead,
		Schema: map[string]*schema.Schema{
			"client_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "MAC address of the client.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Description for the reservation.",
			},
			"ipv4_address": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "The IPv4 address.",
				ValidateFunc: validation.IsIPv4Address,
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The name of the record.",
			},
			"scope_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The DHCP scope.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of client. Either DHCP, BootP or Both.",
			},
		},
	}
}

func dataSourceDHCPLeaseRead(d *schema.ResourceData, meta interface{}) error {
	IPv4Address := d.Get("ipv4_address").(string)

	l, err := winrmhelper.GetDHCPLeaseFromHost(meta.(*config.ProviderConf), IPv4Address)
	if err != nil {
		return err
	}
	if l == nil {
		return fmt.Errorf("No lease found with IP address %q", IPv4Address)
	}
	_ = d.Set("client_id", l.ClientID)
	_ = d.Set("description", l.Description)
	_ = d.Set("name", l.Name)
	_ = d.Set("scope_id", l.ScopeID)
	_ = d.Set("type", l.Type)

	d.SetId(l.IPv4Address)
	return nil
}
