package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
)

type Policy struct {
	types.Attributes
	Role       string     `json:"role"`
	Resource   string     `json:"resource"`
	Permission Permission `json:"permission"`
	IsContent  bool       `json:"isContent"`
}

func (c Policy) New(ctx context.Context) (*Policy,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:New")
	}
	e := errors.Error{
		Package:  "acl",
		Function: "GetBearerToken",
	}
	var err error
	policy := c
	attributesPtr, err := c.Attributes.New(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		e.Err(ctx, err)
		return nil, err
	}
	policy.Attributes = *attributesPtr
	policy.Attributes.ContentType = "policy"
	return &policy, nil
}

func (c Policy) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:ToContent")
	}
	e := errors.Error{
		Package:  "acl",
		Function: "GetBearerToken",
	}
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

func (c Policy) PGRead(ctx context.Context) (*Policy,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGRead")
	}
	e := errors.Error{
		Package:  "acl",
		Function: "GetBearerToken",
	}
	contentPtr, err := types.Content{}.Read(ctx, c.Attributes.Id)
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
	policy := Policy{}
	if content.Content != nil {
		err = json.Unmarshal(content.Content, &policy)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
	} else {
		return nil, nil
	}

	return &policy, nil
}

func (c Policy) PGCreate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGCreate")
	}
	e := errors.Error{
		Package: "acl",
	}
	err := types.Content{}.Create(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Policy) PGUpdate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGUpdate")
	}
	e := errors.Error{
		Package: "acl",
	}
	content, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil
	}
	return content.Update(ctx, c)
}

func (c Policy) PGDelete(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGDelete")
	}
	err := types.Content{}.Delete(ctx, c.Attributes.Id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Policy) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:policy.go:Policy:IsDocument")
	}
	return true
}

func (c Policy) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:ToMSI")
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

type Policies []Policy

func (c Policies) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:policy.go:Policies:In")
	}
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Policies) SelectIn(ctx context.Context) (*Policies,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:SelectIn")
	}
	e := errors.Error{}
	var ids []string
	for _, policy := range c {
		ids = append(ids, policy.Attributes.Id)
	}
	contentsPtr, err := types.Content{}.SelectIn(ctx, ids)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	policies := Policies{}
	for _, contentPtr := range contentsPtr {
		if contentPtr != nil {
			content := *contentPtr
			policy := Policy{}
			err = json.Unmarshal(content.Content, &policy)
			if err != nil {
				e.Err(ctx, err)
				return nil, err
			}
			policies = append(policies, policy)
		}
	}
	return &policies, nil
}

func (c Policies) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:policy.go:Policies:IsDocument")
	}
	return true
}

func (c Policies) FindPolicies(ctx context.Context) (*Policies,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:FindPolicies")
	}
	e := errors.Error{}
	content, err := types.Content{}.FindAll(ctx, "policy")
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	r := Policies{}
	for _, c := range content {
		policy := Policy{}
		err = json.Unmarshal(c.Content, &policy)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		r = append(r, policy)
	}
	return &r, nil
}

func (c Policies) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:ToMSI")
	}
	r := make(map[string]interface{})
	e := errors.Error{}
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

func (c Policies) CreateMany(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:CreateMany")
	}
	contents := make([]types.Content, 0)
	e := errors.Error{}
	for _, policy := range c {
		contentPtr, err := policy.ToContent(ctx)
		if err != nil {
			e.Err(ctx, err)
			return err
		}
		if contentPtr == nil {
			err = fmt.Errorf("content pointer is nil")
			e.Err(ctx, err)
			return err
		}

		contents = append(contents, *contentPtr)
	}
	err := types.Content{}.CreateMany(ctx, contents)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func CreatePolicy(ctx context.Context, name, role, resource string) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:CreatePolicy")
	}
	e := errors.Error{}
	params := Role{}
	params.Attributes.Name = role
	rolePtr, err := GetRole(ctx, params)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if rolePtr != nil {
		pol := NewPolicy(ctx, name, role, resource, rolePtr.DefaultPermisison)
		if pol != nil {
			p := *pol
			err = p.PGCreate(ctx)
			if err != nil {
				e.Err(ctx, err)
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("unable to create policy")
}

func NewPolicy(ctx context.Context, name, role, resource, permission string) *Policy {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:NewPolicy")
	}
	a := types.NewAttributes(ctx, nil)
	if a != nil {
		att := *a
		p := Policy{
			Attributes: att,
			Role:       role,
			Resource:   resource,
			Permission: Permission{
				Name:  permission,
				Value: true,
			},
		}
		return &p
	}
	return nil
}

func GetPolicies(ctx context.Context) (*Policies,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:GetPolicies")
	}
	e := errors.Error{}
	policiesPtr, err := Policies{}.FindPolicies(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if policiesPtr == nil {
		err = fmt.Errorf("policies is nil")
		e.Err(ctx, err)
		return nil, fmt.Errorf("policies is nil")
	}
	return policiesPtr, nil
}

func GetPolicyByRole(ctx context.Context, role string) (*Policies,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:GetPolicyByRole")
	}
	e := errors.Error{}
	dbPoliciesPtr, err := GetPolicies(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if dbPoliciesPtr != nil {
		dbPolicies := *dbPoliciesPtr
		policies := Policies{}
		for _, p := range dbPolicies {
			if p.Role == role {
				policies = append(policies, p)
			}
		}
		return &policies, nil
	}
	err = fmt.Errorf("no policies found for role %s", role)
	e.Err(ctx, err)
	return nil, err
}

func GetPolicyById(ctx context.Context, id string) (*Policy,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:GetPolicyById")
	}
	e := errors.Error{}
	dbPoliciesPtr, err := GetPolicies(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if dbPoliciesPtr != nil {
		dbPolicies := *dbPoliciesPtr
		for _, p := range dbPolicies {
			if p.Attributes.Id == id {
				return &p, nil
			}
		}
	}
	err = fmt.Errorf("no policy for role %s", id)
	e.Err(ctx, err)
	return nil, err
}

func CreateSystemPolicies(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:CreateSystemPolicies")
	}
	e := errors.Error{}
	policies := Policies{}
	pol := NewPolicy(ctx, "system-create-user", "system", "/api/user/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-login", "system", "/api/login", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-index", "system", "/", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-settings", "system", "/settings", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-settings-create-user", "system", "/settings/user/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-dashboard", "system", "/dashboard", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-settings-role-create", "system", "/settings/role/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-settings-role-edit", "system", "/settings/role/edit", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "sytsem-api-role-edit", "system", "/api/role/edit", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-api-role-create", "system", "/api/role/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy(ctx, "system-logout", "system", "/logout", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}

	for _, p := range policies {
		err := p.PGCreate(ctx)
		if err != nil {
			e.Err(ctx, err)
			return err
		}
	}
	return nil
}
