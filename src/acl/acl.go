package acl

import (
	"encoding/json"
	"fmt"
	"inventory/src/db"
	"inventory/src/login"
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
	return content.Update()
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

func (c Policies) IsDocument() bool {
	return true
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
			redis, err := db.NewRedisClient()
			if err != nil {
				return err
			}
			err = redis.CreateJSONDocument(p, "policy", ".", false)
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
	redis, err := db.NewRedisClient()
	if err != nil {
		return nil, err
	}
	redisResponseString, err := redis.ReadJSONDocument("policy", ".")
	if err != nil {
		return nil, err
	}
	if redisResponseString != nil {
		responseString := *redisResponseString
		if responseString != "" {
			if responseString[0] != '[' {
				responseString = fmt.Sprintf("[%s]", responseString)
			}
			policies := Policies{}
			err := json.Unmarshal([]byte(responseString), &policies)
			if err != nil {
				return nil, err
			}
			return &policies, nil
		}
	}
	return nil, fmt.Errorf("no policies found")
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
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	for _, p := range policies {
		err = redis.CreateJSONDocument(p, "policy", ".", false)
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
	return content.Update()
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
	rolesPtr, err := GetRoles()
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

type Roles []Role

func GetRoles() (*Roles, error) {
	roles := Roles{}
	redis, err := db.NewRedisClient()
	if err != nil {
		return nil, err
	}
	redisRepsonseString, err := redis.ReadJSONDocument("role", ".")
	if err != nil {
		return nil, err
	}
	if redisRepsonseString != nil {
		responseString := *redisRepsonseString
		if responseString != "" {
			if responseString[0] != '[' {
				responseString = fmt.Sprintf("[%s]", responseString)
			}
			err = json.Unmarshal([]byte(responseString), &roles)
			if err != nil {
				return nil, err
			}
			return &roles, nil
		}
	}
	return nil, fmt.Errorf("roles not found")
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
	return content.Update()
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

func GetResource(url string) (*Resource, error) {
	redis, err := db.NewRedisClient()
	if err != nil {
		return nil, err
	}

	redisResponseString, err := redis.ReadJSONDocument("resource", ".")
	if err != nil {
		return nil, err
	}
	if redisResponseString != nil {
		responseString := *redisResponseString
		if responseString == "" {
			return nil, nil
		} 
		if responseString[0] != '[' {
			responseString = fmt.Sprintf("[%s]", responseString)
		}
		resources := Resources{}
		err = json.Unmarshal([]byte(responseString), &resources)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
		if r.URL == url {
			return &r, nil
		}
		}
	}

	err = fmt.Errorf("not found")
	return nil, err
}

func authenticateToken(c echo.Context) (map[string]interface{}, error){
	data := make(map[string]interface{})
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		data["Authenticated"] = false
		return data, fmt.Errorf("bearer not found")
	}
	fmt.Printf("bearer: %s\n", bearer)
	bearerParts := strings.Split(bearer, " ")
	var token string
	if len(bearerParts) > 1 {
		token = bearerParts[1]
		fmt.Printf("token: %s\n", token)
	}
	fmt.Printf("request: %s\n\n", c.Request().RequestURI)

	login.ExtendToken(token, []byte("secret"))
	data["Authenticated"] = true
	data["Token"] = token
	return data, nil
}

type Permission struct {
	Name string `json:"name"`
	Value bool `json:"value"`
}

type Permissions []Permission

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