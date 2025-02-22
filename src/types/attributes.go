package types

import (
	"time"

	"github.com/google/uuid"
)

type Attributes struct {
	Id        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedBy string    `json:"createdBy"`
	Owner     string    `json:"owner"`
	Name      string    `json:"name"`
	ContentType string `json:"contentType"`
}

func (c *Attributes) MSIHydrate(msi map[string]interface{}) error {
	if v, ok := msi["id"].(string); ok {
		c.Id = v
	}
	if v, ok := msi["createdAt"].(string); ok {
		t, err := time.Parse("", v)
		if err != nil {
			return err
		}
		c.CreatedAt = t
	}
	if v, ok := msi["updatedAt"].(string); ok {
		t, err := time.Parse("", v)
		if err != nil {
			return err
		}
		c.UpdatedAt = t
	}
	if v, ok := msi["createdBy"].(string); ok {
		c.CreatedBy = v
	}
	if v, ok := msi["owner"].(string); ok {
		c.Owner = v
	}
	if v, ok := msi["name"].(string); ok {
		c.Name = v
	}
	if v, ok := msi["contentType"].(string); ok {
		c.ContentType = v
	}
	return nil
}

func (c Attributes) Merge(old, new Attributes) (*Attributes, error) {
	new.Id = old.Id
	new.CreatedAt = old.CreatedAt
	new.CreatedBy = old.CreatedBy
	new.UpdatedAt = time.Now()
	if new.Owner == "" {
		new.Owner = old.Owner
	}
	if new.Name == "" {
		new.Name = old.Name
	}
	if new.ContentType == "" {
		new.ContentType = old.ContentType
	}
	return &new, nil
} 

func NewAttributes(createdBy *User) *Attributes {
	r := Attributes{
		Id:        uuid.NewString(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if createdBy != nil {
		r.CreatedBy = createdBy.Id
		r.Owner = createdBy.Id
	} else {
		r.CreatedBy = r.Id
		r.Owner = r.Id
	}
	return &r
}
