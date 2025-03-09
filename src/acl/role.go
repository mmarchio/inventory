package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
)

type Role struct {
	types.Attributes
	Policies          Policies `json:"policies"`
	DefaultPermisison string   `json:"defaultPermission"`
}

func (c Role) New(ctx context.Context) (*Role,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:new")
	}
	e := errors.Error{}
	role := c
	attributesPtr, err := c.Attributes.New(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes is nil")
	}

	role.Attributes = *attributesPtr
	role.Attributes.ContentType = "role"
	return &role, nil
}

func (c Role) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:ToContent")
	}
	e := errors.Error{}
	content := types.Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Role) PGRead(ctx context.Context) (*Role,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGRead")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	role := c
	err = json.Unmarshal(content.Content, &role)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &role, nil
}

func (c Role) PGCreate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGCreate")
	}
	err := types.Content{}.Create(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Role) PGUpdate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGUpdate")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return err
	}
	content := *contentPtr
	err = content.Update(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Role) PGDelete(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGDelete")
	}
	err := types.Content{}.Delete(ctx, c.Attributes.Id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return err
}

func (c Role) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:role.go:role:IsDocument")
	}
	return true
}

func (c Role) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:ToMSI")
	}
	e := errors.Error{}
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	return r, nil
}

func GetRole(ctx context.Context, params Role) (*Role,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:GetRole")
	}
	e := errors.Error{}
	rolesPtr, err := FindRoles(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}

	if rolesPtr != nil {
		roles := *rolesPtr
		fmt.Printf("\nroles length: %d\n", len(roles))
		for _, role := range roles {
			if role.Attributes.Id == params.Attributes.Id || role.Attributes.Name == params.Attributes.Name {
				return &role, nil
			}
		}
	}
	err = fmt.Errorf("role params: %#v not found", params)
	e.Err(ctx, err)
	return nil, err
}

func GetRoles(ctx context.Context) (*Roles,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:GetRoles")
	}
	e := errors.Error{
		Package:  "acl",
		Function: "GetRoles",
	}
	if t, ok := ctx.Value(ukey).([]string); ok {
		e.Trace = t
	}

	contents, err := types.Content{}.FindAll(ctx, "role")
	if err != nil {
		e.Err(ctx, err)
		return nil, e
	}
	roles := Roles{}
	for _, content := range contents {
		role := Role{}
		err = json.Unmarshal(content.Content, &role)
		if err != nil {
			return nil, e
		}
		roles = append(roles, role)
	}
	return &roles, nil
}

type Roles []Role

func (c Roles) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:role.go:Roles:GetRole")
	}
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func FindRoles(ctx context.Context) (*Roles,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:Roles:FindRoles")
	}
	e := errors.Error{}
	content, err := types.Content{}.FindAll(ctx, "role")
	if err != nil {
		e.Err(ctx, err)
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
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:role.go:Roles:IsDocument")
	}
	return true
}

func (c Roles) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:Roles:ToMSI")
	}
	e := errors.Error{}
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	return r, nil
}
