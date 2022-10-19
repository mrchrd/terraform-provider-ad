package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func resourceDHCPReservation() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_dhcpreservation` manages DHCP reservations in an Active Directory tree.",
		Create:      resourceDHCPReservationCreate,
		Read:        resourceDHCPReservationRead,
		Update:      resourceDHCPReservationUpdate,
		Delete:      resourceDHCPReservationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"client_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "MAC address of the client.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
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
				Required:    true,
				Description: "The name of the record.",
			},
			"scope_id": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.IsIPv4Address,
				Description:  "The DHCP scope.",
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "Both",
				ValidateFunc: validation.StringInSlice([]string{"DHCP", "BootP", "Both"}, false),
				Description:  "The type of client. Either DHCP, BootP or Both.",
			},
		},
	}
}

func resourceDHCPReservationCreate(d *schema.ResourceData, meta interface{}) error {
	r := winrmhelper.GetDHCPReservationFromResource(d)
	id, err := r.AddDHCPReservation(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId(id)
	return resourceDHCPReservationRead(d, meta)
}

func resourceDHCPReservationRead(d *schema.ResourceData, meta interface{}) error {
	r, err := winrmhelper.GetDHCPReservationFromHost(meta.(*config.ProviderConf), d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "ObjectNotFound") {
			d.SetId("")
			return nil
		}
		return err
	}
	if r == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("client_id", r.ClientID)
	_ = d.Set("description", r.Description)
	_ = d.Set("ipv4_address", r.IPv4Address)
	_ = d.Set("name", r.Name)
	_ = d.Set("scope_id", r.ScopeID)
	_ = d.Set("type", r.Type)

	return nil
}

func resourceDHCPReservationUpdate(d *schema.ResourceData, meta interface{}) error {
	r := winrmhelper.GetDHCPReservationFromResource(d)
	err := r.ModifyDHCPReservation(d, meta.(*config.ProviderConf))
	if err != nil {
		return err
	}
	return resourceDHCPReservationRead(d, meta)
}

func resourceDHCPReservationDelete(d *schema.ResourceData, meta interface{}) error {
	r, err := winrmhelper.GetDHCPReservationFromHost(meta.(*config.ProviderConf), d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "ObjectNotFound") {
			return nil
		}
		return err
	}
	err = r.DeleteDHCPReservation(meta.(*config.ProviderConf))
	if err != nil {
		return fmt.Errorf("while deleting dhcp reservation: %s", err)
	}
	return nil
}
