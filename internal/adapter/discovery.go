package adapter

import "tzsingbox/internal/model"

func (c *Clash) Discovery(reported int) *model.Discovery {
	if c.inventory == nil || c.inventory.Inbounds == nil {
		return nil
	}
	d := &model.Discovery{Inbounds: len(c.inventory.Inbounds), Reported: reported}
	for _, i := range c.inventory.Inbounds {
		d.AuthIdentities += i.AuthCount
		d.UnsupportedAuth += i.AuthUnsupported
		d.Discovered += 1 + len(i.AuthIDs)
	}
	return d
}
