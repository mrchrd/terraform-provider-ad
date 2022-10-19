package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func resourceDNSRecord() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_dnsrecord` manages DNS records in an Active Directory tree.",
		Create:      resourceDNSRecordCreate,
		Read:        resourceDNSRecordRead,
		Update:      resourceDNSRecordUpdate,
		Delete:      resourceDNSRecordDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"dn": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The distinguished name of the DNS record object.",
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
			"ttl": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      -1,
				ValidateFunc: validation.IntAtLeast(0),
				Description:  "Time to live, in seconds.",
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "A",
				ValidateFunc: validation.StringInSlice([]string{"A"}, true),
				Description:  "The type of the record. Only supports `A` for now.",
			},
			"zone": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The DNS zone.",
			},
		},
	}
}

func resourceDNSRecordCreate(d *schema.ResourceData, meta interface{}) error {
	r := winrmhelper.GetDNSRecordFromResource(d)
	id, err := r.AddDNSRecord(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId(id)
	return resourceDNSRecordRead(d, meta)
}

func resourceDNSRecordRead(d *schema.ResourceData, meta interface{}) error {
	r, err := winrmhelper.GetDNSRecordFromHost(meta.(*config.ProviderConf), d.Id())
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
	_ = d.Set("dn", r.DistinguishedName)
	_ = d.Set("ipv4_address", r.IPv4Address)
	_ = d.Set("name", r.Name)
	_ = d.Set("ttl", r.TTL)
	_ = d.Set("type", r.Type)

	return nil
}

func resourceDNSRecordUpdate(d *schema.ResourceData, meta interface{}) error {
	r := winrmhelper.GetDNSRecordFromResource(d)
	err := r.ModifyDNSRecord(d, meta.(*config.ProviderConf))
	if err != nil {
		return err
	}
	return resourceDNSRecordRead(d, meta)
}

func resourceDNSRecordDelete(d *schema.ResourceData, meta interface{}) error {
	r, err := winrmhelper.GetDNSRecordFromHost(meta.(*config.ProviderConf), d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "ObjectNotFound") {
			return nil
		}
		return err
	}
	err = r.DeleteDNSRecord(meta.(*config.ProviderConf))
	if err != nil {
		return fmt.Errorf("while deleting dns record: %s", err)
	}
	return nil
}
