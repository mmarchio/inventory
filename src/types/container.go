package types

type Container struct {
	Attributes Attributes `json:"attributes"`
	Items Items `json:"items"`
}

func NewContainer(createdBy *User) (*Container, error) {
	container := Container{}
	attributesPtr := NewAttributes(createdBy)
	if attributesPtr != nil {
		container.Attributes = *attributesPtr
	}
	return &container, nil
}

func (c Container) IsDocument() bool {
	return true
}

func (c Container) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func (c Container) Hydrate(msi map[string]interface{}) (*Container, error) {
	container := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := container.Attributes.MSIHydrate(v)
		if err != nil {
			return nil, err
		}
	}

	if v, ok := msi["items"].([]map[string]interface{}); ok {
		itemsPtr, err := container.Items.Hydrate(v)
		if err != nil {
			return nil, err
		}
		if itemsPtr != nil {
			container.Items = *itemsPtr
		}
	}
	return &container, nil
}

type Containers []Container

func (c Containers) Hydrate(msi []map[string]interface{}) (*Containers, error) {
	containers := c
	for _, r := range msi {
		container := Container{}
		containerPtr, err := container.Hydrate(r)
		if err != nil {
			return nil, err
		}
		if containerPtr != nil {
			containers = append(containers, *containerPtr)
		}
	}
	return &containers, nil
}