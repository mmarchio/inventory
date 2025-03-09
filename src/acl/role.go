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

func (c Role) New(ctx context.Context) (*Role,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:new")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "New", "Role")
	role := c
	attributesPtr, erp := c.Attributes.New(ctx)
	if erp != nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if attributesPtr == nil {
		fidx := "types:Attributes:New"
		err := fmt.Errorf("attributes is nil")
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}

	role.Attributes = *attributesPtr
	role.Attributes.ContentType = "role"
	return &role, nil
}

func (c Role) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:ToContent")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "ToContent", "Role")
	content := types.Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content.Content = jbytes
	return &content, nil
}

func (c Role) PGRead(ctx context.Context) (*Role,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGRead")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "PGRead", "Role")
	contentPtr, erp := c.ToContent(ctx)
	if erp != nil {
		fidx := "acl:Role:PGRead"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		fidx := "acl:Role:PGRead"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content := *contentPtr
	role := c
	err := json.Unmarshal(content.Content, &role)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	return &role, nil
}

func (c Role) PGCreate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGCreate")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "PGCreate", "Role")
	erp := types.Content{}.Create(ctx, c)
	if erp != nil {
		fidx := "types:Content:Create"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Role) PGUpdate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGUpdate")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "PGUpdate", "Role")
	contentPtr, erp := c.ToContent(ctx)
	if erp != nil {
		fidx := "acl:Role:ToContent"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		fidx := "acl:Role:ToContent"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return &e
	}
	content := *contentPtr
	erp = content.Update(ctx, c)
	if erp != nil {
		fidx := "types:Content:Update"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Role) PGDelete(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:PGDelete")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "PGDelete", "Role")
	erp := types.Content{}.Delete(ctx, c.Attributes.Id)
	if erp != nil {
		fidx := "types:Content:Delete"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Role) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:role.go:role:IsDocument")
	}
	return true
}

func (c Role) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:role:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "ToMSI", "Role")
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	return r, nil
}

func GetRole(ctx context.Context, params Role) (*Role,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:GetRole")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "GetRole", "")
	rolesPtr, erp := FindRoles(ctx)
	if erp != nil {
		fidx := "acl:FindRoles"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
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
	err := fmt.Errorf("role params: %#v not found", params)
	e[idx].Err(ctx, err)
	return nil, &e
}

func GetRoles(ctx context.Context) (*Roles,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:GetRoles")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "GetRoles", "")
	contents, erp := types.Content{}.FindAll(ctx, "role")
	if erp != nil {
		fidx := "types:Content:FindAll"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	roles := Roles{}
	for _, content := range contents {
		role := Role{}
		err := json.Unmarshal(content.Content, &role)
		if err != nil {
			fidx := "json:Unmarshal"
			errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
			return nil, &e
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

func FindRoles(ctx context.Context) (*Roles,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:Roles:FindRoles")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "FindRoles", "")
	content, erp := types.Content{}.FindAll(ctx, "role")
	if erp != nil {
		fidx := "types:Content:FindAll"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	r := Roles{}
	for _, c := range content {
		role := Role{}
		err := json.Unmarshal(c.Content, &role)
		if err != nil {
			fidx := "json:Unmarshal"
			errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
			return nil, &e
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

func (c Roles) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:role.go:Roles:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "role.go", "acl", "ToMSI", "Roles")
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	return r, nil
}
