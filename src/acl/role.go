package acl

import (
	"encoding/json"
	"fmt"
	"inventory/src/types"
)

type Role struct {
	types.Attributes
	Name string `json:"name"`
	Policies Policies `json:"policies"`
	DefaultPermisison string `json:"defaultPermission"`
}

func (c Role) New() (*Role, error) {
	role := c
	attributesPtr, err := c.Attributes.New()
	if err != nil {
		return nil, err
	}
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes is nil")
	}

	role.Attributes = *attributesPtr
	role.Attributes.ContentType = "role"
	return &role, nil
}

func (c Role) ToContent() (*types.Content, error) {
	content := types.Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Role) PGRead() (*Role, error) {
	contentPtr, err := c.ToContent()
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	role := c
	err = json.Unmarshal(content.Content, &role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (c Role) PGCreate() error {
	return types.Content{}.Create(c)
}

func (c Role) PGUpdate() error {
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

func (c Role) PGDelete() error {
	return types.Content{}.Delete(c.Attributes.Id)
}

func (c Role) IsDocument() bool {
	return true
}

func (c Role) ToMSI() (map[string]interface{}, error) {
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

func GetRole(id string) (*Role, error) {
	rolesPtr, err := FindRoles()
	if err != nil {
		return nil, err
	}
	if rolesPtr != nil {
		roles := *rolesPtr
		for _, role := range roles {
			if role.Id == id || role.Name == id {
				return &role, nil
			}
		}
	}
	return nil, fmt.Errorf("role id: %s not found", id)
}

func GetRoles() (*Roles, error) {
	contents, err := types.Content{}.FindAll("role")
	if err != nil {
		return nil, err
	}
	roles := Roles{}
	for _, content := range contents {
		role := Role{}
		err = json.Unmarshal(content.Content, &role)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return &roles, nil
}

type Roles []Role

func (c Roles) In(id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func FindRoles() (*Roles, error) {
	content, err := types.Content{}.FindAll("role")
	if err != nil {
		return nil, err
	}
	r := Roles{}
	for _, c := range content {
		role := Role{}
		err = json.Unmarshal(c.Content, &role)
		if err != nil {
			return nil, err
		}
		r = append(r, role)
	}
	return &r, nil
}

func (c Roles) IsDocument() bool {
	return true
}

func (c Roles) ToMSI() (map[string]interface{}, error) {
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		return r, err
	}
	return r, nil
}
