package types

type Zone struct {
	Attributes Attributes `json:"attributes"`
	Containers Containers `json:"containers"`
}

func NewZone(createdBy *User) (*Zone, error) {
	zone := Zone{}
	attributesPtr := NewAttributes(createdBy)
	if attributesPtr != nil {
		zone.Attributes = *attributesPtr
	}
	return &zone, nil
}

func (c Zone) IsDocument() bool {
	return true
}

func (c Zone) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func (c Zone) Hydrate(msi map[string]interface{}) (*Zone, error) {
	zone := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := zone.Attributes.MSIHydrate(v)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := msi["containers"].([]map[string]interface{}); ok {
		containersPtr, err := c.Containers.Hydrate(v)
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

func (c Zones) Hydrate(msi []map[string]interface{}) (*Zones, error) {
	zones := Zones{}
	for _, r := range msi {
		zonePtr := &Zone{}
		zonePtr, err := zonePtr.Hydrate(r)
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