package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/types"

	"github.com/google/uuid"
)

type Resource struct {
	types.Attributes
	Id string `json:"id"`
	URL string `json:"url"`
}

func (c Resource) New(ctx context.Context) (*Resource, error) {
	resource := c
	resource.Id = uuid.NewString()
	return &resource, nil
}

func (c Resource) ToContent(ctx context.Context) (*types.Content, error) {
	content := types.Content{}
	content.Attributes.Id = c.Id
	content.Attributes.ContentType = "resource"
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Resource) PGRead(ctx context.Context) (*Resource, error) {
	contentPtr, err := types.Content{}.Read(ctx, c.Id)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	resource := c
	err = json.Unmarshal(content.Content, &resource)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

func (c Resource) PGCreate(ctx context.Context) error {
	return types.Content{}.Create(ctx, c)
}

func (c Resource) PGUpdate(ctx context.Context) error {
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		return err
	}
	if contentPtr == nil {
		return fmt.Errorf("content is nil")
	}
	content := *contentPtr
	return content.Update(ctx, c)
}

func (c Resource) PGDelete(ctx context.Context) error {
	return types.Content{}.Delete(ctx, c.Attributes.Id)
}

func (c Resource) IsDocument() bool {
	return true
}

func (c Resource) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		return r, err
	}
	return r, nil
}

type Resources []Resource

func (c Resources) In(ctx context.Context, id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Resources) IsDocument(ctx context.Context) bool {
	return true
}

func (c Resources) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		return r, err
	}
	return r, nil
}

func FindResources(ctx context.Context) (*Resources, error) {
	content, err := types.Content{}.FindAll(ctx, "resource")
	if err != nil {
		return nil, err
	}
	r := Resources{}
	for _, c := range content {
		resource := Resource{}
		err = json.Unmarshal(c.Content, &resource)
		if err != nil {
			return nil, err
		}
		r = append(r, resource)
	}
	return &r, nil
}
