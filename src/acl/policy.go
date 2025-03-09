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

func (c Policy) New(ctx context.Context) (*Policy,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:New")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "New", "Policy")
	var err error
	policy := c
	attributesPtr, erp := c.Attributes.New(ctx)
	if erp != nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	policy.Attributes = *attributesPtr
	policy.Attributes.ContentType = "policy"
	return &policy, nil
}

func (c Policy) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:ToContent")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "ToContent", "Policy")
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

func (c Policy) PGRead(ctx context.Context) (*Policy,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGRead")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "PGRead", "Policy")
	contentPtr, erp := types.Content{}.Read(ctx, c.Attributes.Id)
	if erp != nil {
		fidx := "types:Content:Read"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		fidx := "types:Content:Read"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content := *contentPtr
	policy := Policy{}
	if content.Content != nil {
		err := json.Unmarshal(content.Content, &policy)
		if err != nil {
			fidx := "json:Unmarshal"
			errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
			return nil, &e
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
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "PGCreate", "Policy")
	erp := types.Content{}.Create(ctx, c)
	if erp != nil {
		fidx := "types:Content:Create"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Policy) PGUpdate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGUpdate")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "PGUpdate", "Policy")
	content, erp := c.ToContent(ctx)
	if erp != nil {
		fidx := "acl:Policy:ToContent"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	erp = content.Update(ctx, c)
	if erp != nil {
		fidx := "types:Content:Update"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Policy) PGDelete(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:PGDelete")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "PGDelete", "Policy")
	erp := types.Content{}.Delete(ctx, c.Attributes.Id)
	if erp != nil {
		fidx := "types:Content:Delete"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Policy) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:policy.go:Policy:IsDocument")
	}
	return true
}

func (c Policy) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policy:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "ToMSI", "Policy")
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

func (c Policies) SelectIn(ctx context.Context) (*Policies,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:SelectIn")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "SelectIn", "Policies")
	var ids []string
	for _, policy := range c {
		ids = append(ids, policy.Attributes.Id)
	}
	contentsPtr, erp := types.Content{}.SelectIn(ctx, ids)
	if erp != nil {
		fidx := "types:Content:SelectIn"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	policies := Policies{}
	for _, contentPtr := range contentsPtr {
		if contentPtr != nil {
			content := *contentPtr
			policy := Policy{}
			err := json.Unmarshal(content.Content, &policy)
			if err != nil {
				fidx := "json:Unmarshal"
				errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
				return nil, &e
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

func (c Policies) FindPolicies(ctx context.Context) (*Policies,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:FindPolicies")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "SelectIn", "Policies")
	content, erp := types.Content{}.FindAll(ctx, "policy")
	if erp != nil {
		fidx := "types:Content:FindAll"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	r := Policies{}
	for _, c := range content {
		policy := Policy{}
		err := json.Unmarshal(c.Content, &policy)
		if err != nil {
			fidx := "json:Unmarshal"
			errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
			return nil, &e
		}
		r = append(r, policy)
	}
	return &r, nil
}

func (c Policies) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:ToMSI")
	}
	r := make(map[string]interface{})
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "ToMSI", "Policies")
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

func (c Policies) CreateMany(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:Policies:CreateMany")
	}
	contents := make([]types.Content, 0)
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "CreateMany", "Policies")
	for _, policy := range c {
		contentPtr, erp := policy.ToContent(ctx)
		if erp != nil {
			fidx := "acl:Policy:ToContent"
			errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
			return &e
		}
		if contentPtr == nil {
			err := fmt.Errorf("content pointer is nil")
			fidx := "acl:Policy:ToContent"
			errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
			return &e
		}

		contents = append(contents, *contentPtr)
	}
	erp := types.Content{}.CreateMany(ctx, contents)
	if erp != nil {
		fidx := "types:Content:CreateMany"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func CreatePolicy(ctx context.Context, name, role, resource string) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:CreatePolicy")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "CreatePolicy", "")
	params := Role{}
	params.Attributes.Name = role
	rolePtr, erp := GetRole(ctx, params)
	if erp != nil {
		fidx := "acl:GetRole"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	if rolePtr != nil {
		pol := NewPolicy(ctx, name, role, resource, rolePtr.DefaultPermisison)
		if pol != nil {
			p := *pol
			erp = p.PGCreate(ctx)
			if erp != nil {
				fidx := "acl:Policy:PGCreate"
				errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
				return &e
			}
			return nil
		}
	}
	err := fmt.Errorf("unable to create policy")
	e[idx].Err(ctx, err)	
	return &e
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

func GetPolicies(ctx context.Context) (*Policies,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:GetPolicies")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "GetPolicies", "")
	policiesPtr, erp := Policies{}.FindPolicies(ctx)
	if erp != nil {
		fidx := "acl:Policies:FindPolicies"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if policiesPtr == nil {
		err := fmt.Errorf("policies is nil")
		fidx := "acl:Policies:FindPolicies"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	return policiesPtr, nil
}

func GetPolicyByRole(ctx context.Context, role string) (*Policies,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:GetPolicyByRole")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "GetPolicyByRole", "")
	dbPoliciesPtr, erp := GetPolicies(ctx)
	if erp != nil {
		fidx := "acl:GetPolicies"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
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
	err := fmt.Errorf("no policies found for role %s", role)
	e[idx].Err(ctx, err)
	return nil, &e
}

func GetPolicyById(ctx context.Context, id string) (*Policy,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:GetPolicyById")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "CreatePolicy", "")
	dbPoliciesPtr, erp := GetPolicies(ctx)
	if erp != nil {
		fidx := "acl:GetPolicies"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if dbPoliciesPtr != nil {
		dbPolicies := *dbPoliciesPtr
		for _, p := range dbPolicies {
			if p.Attributes.Id == id {
				return &p, nil
			}
		}
	}
	err := fmt.Errorf("no policy for role %s", id)
	e[idx].Err(ctx, err)
	return nil, &e
}

func CreateSystemPolicies(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:policy.go:CreateSystemPolicies")
	}
	e, idx := errors.Error{}.New(ctx, "policy.go", "acl", "CreatePolicy", "")
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
		erp := p.PGCreate(ctx)
		if erp != nil {
			fidx := "acl:Policy:Create"
			errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
			return &e
		}
	}
	return nil
}
