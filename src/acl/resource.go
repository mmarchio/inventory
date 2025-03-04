package acl

import (
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

func (c Resource) New() (*Resource, error) {
	resource := c
	resource.Id = uuid.NewString()
	return &resource, nil
}

func (c Resource) ToContent() (*types.Content, error) {
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

func (c Resource) PGRead() (*Resource, error) {
	contentPtr, err := types.Content{}.Read(c.Id)
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

func (c Resource) PGCreate() error {
	return types.Content{}.Create(c)
}

func (c Resource) PGUpdate() error {
	contentPtr, err := c.ToContent()
	if err != nil {
		return err
	}
	if contentPtr == nil {
		return fmt.Errorf("content is nil")
	}
	content := *contentPtr
	return content.Update(c)
}

func (c Resource) PGDelete() error {
	return types.Content{}.Delete(c.Attributes.Id)
}

func (c Resource) IsDocument() bool {
	return true
}

func (c Resource) ToMSI() (map[string]interface{}, error) {
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

func (c Resources) In(id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Resources) IsDocument() bool {
	return true
}

func (c Resources) ToMSI() (map[string]interface{}, error) {
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

func FindResources() (*Resources, error) {
	content, err := types.Content{}.FindAll("resource")
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

