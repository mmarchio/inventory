package types

type Address struct {
	Attributes
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
	City string `json:"city"`
	State string `json:"state"`
	Zipcode string `json:"zipcode"`
	Country string `json:"country"`
}

func NewAddress(createdBy *User) (*Address, error) {
	address := Address{}
	attributesPtr := NewAttributes(createdBy)
	if attributesPtr != nil {
		address.Attributes = *attributesPtr
	}
	return &address, nil
}

func (c Address) Merge(old, new Address) (*Address, error) {
	attributesPtr, err := old.Attributes.Merge(old.Attributes, new.Attributes)
	if err != nil {
		return nil, err
	}
	if attributesPtr != nil {
		new.Attributes = *attributesPtr
	}
	if new.Address1 == "" {
		new.Address1 = old.Address1
	}
	if new.Address2 == "" {
		new.Address2 = old.Address2
	}
	if new.City == "" {
		new.City = old.City
	}
	if new.State == "" {
		new.State = old.State
	}
	if new.Country == "" {
		new.Country = old.Country
	}
	return &new, nil
}

func (c Address) IsDocument() bool {
	return true
}

func (c Address) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func (c Address) Hydrate(msi map[string]interface{}) (*Address, error) {
	address := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := c.Attributes.MSIHydrate(v)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := msi["address1"].(string); ok {
		address.Address1 = v
	}

	if v, ok := msi["address2"].(string); ok {
		address.Address2 = v
	}

	if v, ok := msi["city"].(string); ok {
		address.City = v
	}

	if v, ok := msi["state"].(string); ok {
		address.State = v
	}

	if v, ok := msi["zipcode"].(string); ok {
		address.Zipcode = v
	}

	if v, ok := msi["country"].(string); ok {
		address.Country = v
	}

	return &address, nil
}