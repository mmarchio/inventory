package acl

import (
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

func (c Policy) New() (*Policy, error) {
	var err error
	policy := c
	attributesPtr, err := c.Attributes.New()
	if err != nil {
		return nil, err
	}
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes is nil")
	}
	policy.Attributes = *attributesPtr
	if err != nil {
		return nil, err
	}
	policy.Attributes.ContentType = "policy"
	return &policy, nil
}

func (c Policy) ToContent() (*types.Content, error) {
	content := types.Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Policy) PGRead() (*Policy, error) {
	contentPtr, err := types.Content{}.Read(c.Attributes.Id)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	policy := c
	err = json.Unmarshal(content.Content, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func (c Policy) PGCreate() error {
	contentPtr, err := c.PGRead()
	if err != nil {
		fmt.Println("\ntrace(3): policy:PGCreate:read:err\n")
		return err
	}
	if contentPtr == nil {
		fmt.Println("\ntrace(4): policy:PGCreate:content:isNil\n")
		return types.Content{}.Create(c)
	}
	return nil
}

func (c Policy) PGUpdate() error {
	content, err := c.ToContent()
	if err != nil {
		return nil
	}
	return content.Update(c)
}

func (c Policy) PGDelete() error {
	return types.Content{}.Delete(c.Attributes.Id)
}

func (c Policy) IsDocument() bool {
	return true
}

func (c Policy) ToMSI() (map[string]interface{}, error) {
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

func (c Policies) In(id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Policies) IsDocument() bool {
	return true
}

func (c Policies) FindPolicies() (*Policies, error) {
	content, err := types.Content{}.FindAll("policy")
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

func (c Policies) ToMSI() (map[string]interface{}, error) {
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

func CreatePolicy(name, role, resource string) error {
	rolePtr, err := GetRole(role)
	if err != nil {
		return err
	}
	if rolePtr != nil {
		pol := NewPolicy(name, role, resource, rolePtr.DefaultPermisison)
		if pol != nil {
			p := *pol
			err = p.PGCreate()
			if err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("unable to create policy")
}

func NewPolicy(name, role, resource, permission string) *Policy {
	a := types.NewAttributes(nil)
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

func GetPolicies() (*Policies, error) {
	policiesPtr, err := Policies{}.FindPolicies()
	if err != nil {
		return nil, err
	}
	if policiesPtr == nil {
		return nil, fmt.Errorf("policies is nil")
	}
	return policiesPtr, nil
}

func GetPolicyByRole(role string) (*Policies, error) {
	dbPoliciesPtr, err := GetPolicies()
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

func GetPolicyById(id string) (*Policy, error) {
	dbPoliciesPtr, err := GetPolicies()
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

func CreateSystemPolicies() error {
	policies := Policies{}
	pol := NewPolicy("system-create-user", "system", "/api/user/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-login", "system", "/api/login", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-index", "system", "/", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-settings", "system", "/settings", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-settings-create-user", "system", "/settings/user/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-dashboard", "system", "/dashboard", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-settings-role-create", "system", "/settings/role/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-settings-role-edit", "system", "/settings/role/edit", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("sytsem-api-role-edit", "system", "/api/role/edit", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-api-role-create", "system", "/api/role/create", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}
	pol = NewPolicy("system-logout", "system", "/logout", "all")
	if pol != nil {
		policies = append(policies, *pol)
	}

	for _, p := range policies {
		fmt.Println("\ntrace(1): acl:createsystempolicies:iterate\n")
		err := p.PGCreate()
		if err != nil {
			fmt.Println("\ntrace(2): acl:createsystempolicies:iterate:err\n")
			return err
		}
	}
	return nil
}
