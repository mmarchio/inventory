package acl

import (
	"encoding/json"
	"fmt"
	"inventory/src/types"
	"log"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/google/uuid"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags | log.Lshortfile)

type Policy struct {
	types.Attributes
	Role string `json:"role"`
	Resource string `json:"resource"`
	Permission Permission `json:"permission"`
	IsContent bool `json:"isContent"`
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
	return types.Content{}.Create(c)
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
			Role: role,
			Resource: resource,
			Permission: Permission{
				Name: permission,
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
		err := p.PGCreate()
		if err != nil {
			return err
		}
	}
	return nil
}

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

type Permission struct {
	Name string `json:"name"`
	Value bool `json:"value"`
}

type Permissions []Permission

func FindPermissions() (*Permissions, error) {
	content, err := types.Content{}.FindAll("permission")
	if err != nil {
		return nil, err
	}
	r := Permissions{}
	for _, c := range content {
		permission := Permission{}
		err = json.Unmarshal(c.Content, &permission)
		if err != nil {
			return nil, err
		}
		r = append(r, permission)
	}
	return &r, nil
}

func GetBearerToken(c echo.Context) (string, error) {
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		err := fmt.Errorf("authorization header not found")
		return "", err
	}
	parts := strings.Split(bearer, " ")
	if len(parts) != 2 {
		err := fmt.Errorf("unexpected authorization header segments")
		return "", err
	}
	return parts[1], nil
}

func GetUserFromContext(c echo.Context) (*types.User, error) {
	token, err := GetBearerToken(c)
	if err != nil {
		return nil, err
	}
	jwt, err := DecodeJWT(token, []byte("secret"))
	if err != nil {
		return nil, err
	}
	userPtr, err := GetUser(jwt)
	if err != nil {
		return nil, err
	}
	return userPtr, nil
}