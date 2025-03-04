package types

import "context"

type Zone struct {
	Attributes Attributes `json:"attributes"`
	Containers Containers `json:"containers"`
}

func NewZone(ctx context.Context, createdBy *User) (*Zone, error) {
	zone := Zone{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		zone.Attributes = *attributesPtr
	}
	return &zone, nil
}

func (c Zone) IsDocument(ctx context.Context) bool {
	return true
}

func (c Zone) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	return toMSI(ctx, c)
}

func (c Zone) Hydrate(ctx context.Context, msi map[string]interface{}) (*Zone, error) {
	zone := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := zone.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := msi["containers"].([]map[string]interface{}); ok {
		containersPtr, err := c.Containers.Hydrate(ctx, v)
		if err != nil {
			return nil, err
		}
		if containersPtr != nil {
			zone.Containers = *containersPtr
		}
	}
	return &zone, nil
}

type Zones []Zone

func (c Zones) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Zones, error) {
	zones := Zones{}
	for _, r := range msi {
		zonePtr := &Zone{}
		zonePtr, err := zonePtr.Hydrate(ctx, r)
		if err != nil {
			return nil, err
		}
		if zonePtr != nil {
			zone := *zonePtr
			zones = append(zones, zone)
		}
	}
	return &zones, nil
}

func (c Zones) In(ctx context.Context, id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}