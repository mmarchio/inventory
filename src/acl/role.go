package acl

import (
	"context"
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

func (c Role) New(ctx context.Context) (*Role, error) {
	role := c
	attributesPtr, err := c.Attributes.New(ctx)
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

func (c Role) ToContent(ctx context.Context) (*types.Content, error) {
	content := types.Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Role) PGRead(ctx context.Context) (*Role, error) {
	contentPtr, err := c.ToContent(ctx)
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

func (c Role) PGCreate(ctx context.Context) error {
	return types.Content{}.Create(ctx, c)
}

func (c Role) PGUpdate(ctx context.Context) error {
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

func (c Role) PGDelete(ctx context.Context) error {
	return types.Content{}.Delete(ctx, c.Attributes.Id)
}

func (c Role) IsDocument(ctx context.Context) bool {
	return true
}

func (c Role) ToMSI(ctx context.Context) (map[string]interface{}, error) {
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

func GetRole(ctx context.Context, id string) (*Role, error) {
	rolesPtr, err := FindRoles(ctx)
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

func GetRoles(ctx context.Context) (*Roles, error) {
	contents, err := types.Content{}.FindAll(ctx, "role")
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

func (c Roles) In(ctx context.Context, id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func FindRoles(ctx context.Context) (*Roles, error) {
	content, err := types.Content{}.FindAll(ctx, "role")
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

func (c Roles) IsDocument(ctx context.Context) bool {
	return true
}

func (c Roles) ToMSI(ctx context.Context) (map[string]interface{}, error) {
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
