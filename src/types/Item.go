package types

type Item struct {
	Attributes Attributes `json:"attributes"`
	Quantity float64 `json:"quantity"`
	UOMS string `json:"oums"`
}

func NewItem(createdBy *User) (*Item, error) {
	item := Item{}
	attributesPtr := NewAttributes(createdBy)
	if attributesPtr != nil {
		item.Attributes = *attributesPtr
	}
	return &item, nil
}

func (c Item) IsDocument() bool {
	return true
}

func (c Item) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func (c Item) Hydrate(msi map[string]interface{}) (*Item, error) {
	r := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := r.Attributes.MSIHydrate(v)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := msi["quantity"].(float64); ok {
		r.Quantity = v
	}

	if v, ok := msi["uoms"].(string); ok {
		r.UOMS = v
	}

	return &r, nil
}

type Items []Item 

func (c Items) Hydrate(msi []map[string]interface{}) (*Items, error) {
	items := c
	for _, r := range msi {
		item := Item{}
		itemPtr, err := item.Hydrate(r)
		if err != nil {
			return nil, err
		}
		if itemPtr != nil {
			items = append(items, *itemPtr)
		}
	}
	return &items, nil
}