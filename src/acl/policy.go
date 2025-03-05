package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/types"
)

type Policy struct {
	
	types.Attributes
	Role       string     `json:"role"`
	Resource   string     `json:"resource"`
	Permission Permission `json:"permission"`
	IsContent  bool       `json:"isContent"`
}

func (c Policy) New(ctx context.Context) (*Policy, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:New")
	}
	var err error
	policy := c
	attributesPtr, err := c.Attributes.New(ctx)
	if err != nil {
		return nil, err
	}
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes is nil")
	}
	policy.Attributes = *attributesPtr
	policy.Attributes.ContentType = "policy"
	return &policy, nil
}

func (c Policy) ToContent(ctx context.Context) (*types.Content, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:ToContent")
	}
	content := types.Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Policy) PGRead(ctx context.Context) (*Policy, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:PGRead")
	}
	contentPtr, err := types.Content{}.Read(ctx, c.Attributes.Id)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	policy := Policy{}
	if content.Content != nil {
		err = json.Unmarshal(content.Content, &policy)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}

	return &policy, nil
}

func (c Policy) PGCreate(ctx context.Context) error {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:PGCreate")
	}
	return types.Content{}.Create(ctx, c)
}

func (c Policy) PGUpdate(ctx context.Context) error {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:PGUpdate")
	}
	content, err := c.ToContent(ctx)
	if err != nil {
		return nil
	}
	return content.Update(ctx, c)
}

func (c Policy) PGDelete(ctx context.Context) error {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:PGDelete")
	}
	return types.Content{}.Delete(ctx, c.Attributes.Id)
}

func (c Policy) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:IsDocument")
	}
	return true
}

func (c Policy) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policy:ToMSI")
	}
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

type Policies []Policy

func (c Policies) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policies:In")
	}
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Policies) SelectIn(ctx context.Context) (*Policies, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policies:SelectIn")
	}
	var ids []string
	for _, policy := range c {
		ids = append(ids, policy.Attributes.Id)
	}
	contentsPtr, err := types.Content{}.SelectIn(ctx, ids)
	if err != nil {
		return nil, err
	}
	policies := Policies{}
	for _, contentPtr := range contentsPtr {
		if contentPtr != nil {
			content := *contentPtr
			policy := Policy{}
			err = json.Unmarshal(content.Content, &policy)
			if err != nil {
				return nil, err
			}
			policies = append(policies, policy)
		}
	}
	return &policies, nil
}

func (c Policies) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policies:IsDocument")
	}
	return true
}

func (c Policies) FindPolicies(ctx context.Context) (*Policies, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policies:FindPolicies")
	}
	content, err := types.Content{}.FindAll(ctx, "policy")
	if err != nil {
		return nil, err
	}
	r := Policies{}
	for _, c := range content {
		policy := Policy{}
		err = json.Unmarshal(c.Content, &policy)
		if err != nil {
			return nil, err
		}
		r = append(r, policy)
	}
	return &r, nil
}

func (c Policies) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policies:ToMSI")
	}
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

func (c Policies) CreateMany(ctx context.Context) error {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:Policies:CreateMany")
	}
	contents := make([]types.Content, 0)
	for _, policy := range c {
		contentPtr, err := policy.ToContent(ctx)
		if err != nil {
			return err
		}
		if contentPtr == nil {
			return fmt.Errorf("content pointer is nil")
		}
	
		contents = append(contents, *contentPtr)
	}
	err := types.Content{}.CreateMany(ctx, contents)
	if err != nil {
		return err
	}
	return nil
}

func CreatePolicy(ctx context.Context, name, role, resource string) error {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:CreatePolicy")
	}
	rolePtr, err := GetRole(ctx, role)
	if err != nil {
		return err
	}
	if rolePtr != nil {
		pol := NewPolicy(ctx, name, role, resource, rolePtr.DefaultPermisison)
		if pol != nil {
			p := *pol
			err = p.PGCreate(ctx)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("unable to create policy")
}

func NewPolicy(ctx context.Context, name, role, resource, permission string) *Policy {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:NewPolicy")
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

func GetPolicies(ctx context.Context) (*Policies, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:GetPolicies")
	}
	policiesPtr, err := Policies{}.FindPolicies(ctx)
	if err != nil {
		return nil, err
	}
	if policiesPtr == nil {
		return nil, fmt.Errorf("policies is nil")
	}
	return policiesPtr, nil
}

func GetPolicyByRole(ctx context.Context, role string) (*Policies, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:GetPolicyByRole")
	}
	dbPoliciesPtr, err := GetPolicies(ctx)
	if err != nil {
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
	return nil, fmt.Errorf("no policies found for role %s", role)
}

func GetPolicyById(ctx context.Context, id string) (*Policy, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:GetPolicyById")
	}
	dbPoliciesPtr, err := GetPolicies(ctx)
	if err != nil {
		return nil, err
	}
	if dbPoliciesPtr != nil {
		dbPolicies := *dbPoliciesPtr
		for _, p := range dbPolicies {
			if p.Id == id {
				return &p, nil
			}
		}
	}
	return nil, fmt.Errorf("no policy found for role %s", id)
}

func CreateSystemPolicies(ctx context.Context) error {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl:policy.go:CreateSystemPolicies")
	}
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
			return err
		}
	}
	return nil
}
