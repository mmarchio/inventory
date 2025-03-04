package types

import "context"

type Container struct {
	Attributes Attributes `json:"attributes"`
	Items      Items      `json:"items"`
}

func NewContainer(ctx context.Context, createdBy *User) (*Container, error) {
	container := Container{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		container.Attributes = *attributesPtr
	}
	return &container, nil
}

func (c Container) IsDocument(ctx context.Context) bool {
	return true
}

func (c Container) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	return toMSI(ctx, c)
}

func (c Container) Hydrate(ctx context.Context, msi map[string]interface{}) (*Container, error) {
	container := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := container.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			return nil, err
		}
	}

	if v, ok := msi["items"].([]map[string]interface{}); ok {
		itemsPtr, err := container.Items.Hydrate(ctx, v)
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

func (c Containers) In(id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Containers) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Containers, error) {
	containers := c
	for _, r := range msi {
		container := Container{}
		containerPtr, err := container.Hydrate(ctx, r)
		if err != nil {
			return nil, err
		}
		if containerPtr != nil {
			containers = append(containers, *containerPtr)
		}
	}
	return &containers, nil
}