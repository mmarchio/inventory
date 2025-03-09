package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/login"
	"inventory/src/util"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
)

const ERRORTPL = "error.tpl.html"

var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type IDocument interface {
	IsDocument() bool
	ToMSI() (map[string]interface{}, *map[string]errors.Error)

	Hydrate(map[string]interface{}) error
}

func GetRequestData(ctx context.Context, c echo.Context) (*map[string]interface{}, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:GetRequestData")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "GetRequestData", "")
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		e["controller:GetRequestData"].Err(ctx, err)
		return nil, &e
	}
	return &body, nil
}

func authenticateToken(ctx context.Context, c echo.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:authenticateToken")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "authenticateToken", "")
	data := make(map[string]interface{})
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		data["Authenticated"] = false
		ca := e["controller:authenticateToke"]
		ca.Recoverable = true
		e["controller:authenticateToken"] = ca
		e["controller:authenticateToken"].Err(ctx, fmt.Errorf("bearer not found"))
		return data, &e
	}
	bearerParts := strings.Split(bearer, " ")
	var token string
	if len(bearerParts) > 1 {
		token = bearerParts[1]
	}
	data["Token"] = token
	_, erp := acl.DecodeJWT(ctx, token, []byte("secret"))
	if erp != nil {
		ers := *erp
		e["acl:DecodeJWT"] = e["controller:authenticateToken"]
		e["acl:DecodeJWT"].Err(ctx, ers["acl:DecodeJWT"].Wrapper)
		data["error"] = ers["acl:DecodeJWT"].Wrapper
		return data, &e
	}
	tokenPtr, erp := login.ExtendToken(ctx, token, []byte("secret"))
	if erp != nil {
		ers := *erp
		e["login:ExtendToken"] = e["controller:authenticateToken"]
		e["login:ExtendToken"].Err(ctx, ers["controller:ExtendToken"].Wrapper)
		return data, &e
	}
	if tokenPtr != nil {
		data["Token"] = token
	}
	data["Authenticated"] = true
	return data, nil
}

func CreatePolicy(ctx context.Context, resource, role, permission string) (*acl.Policy,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:CreatePolicy")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "CreatePolicy", "")
	segments := strings.Split(resource, "/")
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	last := segments[len(segments)-1]
	var name string
	if r.Match([]byte(last)) {
		resource = strings.Join(segments[0:len(segments)-2], "/")
		name = fmt.Sprintf("%s-%s", role, strings.Join(segments[0:len(segments)-2], "-"))
	} else {
		name = fmt.Sprintf("%s-%s", role, strings.Join(segments[0:len(segments)-1], "-"))
	}
	polPtr := acl.NewPolicy(ctx, name, role, resource, permission)
	if polPtr != nil {
		return polPtr, nil
	}
	err := fmt.Errorf("unable to create policy")
	e["controller:CreatePolicy"].Err(ctx, err)
	return nil, &e
}

func UpdateRole(ctx context.Context, id string, resources acl.Resources) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:UpdateRole")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "UpdateRole", "")
	params := acl.Role{}
	params.Attributes.Id = id
	rolePtr, erp := acl.GetRole(ctx, params)
	if erp != nil {
		ers := *erp
		e["controller:UpdateRole"].Err(ctx, ers["controller:GetRole"].Wrapper)
		return &e
	}
	var role acl.Role
	if rolePtr != nil {
		role = *rolePtr
	}
	for _, resource := range resources {
		polPtr, erp := CreatePolicy(ctx, resource.URL, role.Attributes.Name, role.DefaultPermisison)
		if erp != nil || polPtr == nil {
			ers := *erp
			e["controller:CreatePolicy"] = e["controller:UpdateRole"]
			e["controller:CreatePolicy"].Err(ctx, ers["controller:CreatePolicy"].Wrapper)
			return &e
		}
		role.Policies = append(role.Policies, *polPtr)
	}
	erp = role.PGCreate(ctx)
	if erp != nil {
		ers := *erp
		e["role:PGCreate"] = e["controller:UpdateRole"]
		e["role:PGCreate"].Err(ctx, ers["role:PGCreate"].Wrapper)
		return &e
	}
	return nil
}

func UpdatePolicy(ctx context.Context, role string, resources acl.Resources) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:UpdatePolicy")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "UpdatePolicy", "")
	dbPoliciesPtr, erp := acl.GetPolicyByRole(ctx, role)
	if erp != nil {
		ers := *erp
		e["acl:GetPolicyByRole"] = e["controller:UpdatePolicy"]
		e["acl:GetPolicyByRole"].Err(ctx, ers["acl:GetPolicyByRole"].Wrapper)
		return &e
	}
	if dbPoliciesPtr != nil {
		dbPolicies := *dbPoliciesPtr
	OUTER:
		for _, outer := range resources {
			for _, inner := range dbPolicies {
				if outer.URL == inner.Resource {
					continue OUTER
				}
			}
			segments := strings.Split(outer.URL, "/")
			segments = append([]string{role}, segments...)
			params := acl.Role{}
			params.Attributes.Name = role
			rolePtr, erp := acl.GetRole(ctx, params)
			if erp != nil {
				ers := *erp
				e["acl:GetRole"] = e["controller:UpdatePolicy"]
				e["acl:GetRole"].Err(ctx, ers["acl:GetRole"].Wrapper)
				return &e
			}
			if rolePtr != nil {
				polPtr := acl.NewPolicy(ctx, strings.Join(segments, "-"), role, outer.URL, rolePtr.DefaultPermisison)
				if polPtr != nil {
					pol := *polPtr
					dbPolicies = append(dbPolicies, pol)
				}
			}
		}
		for _, policy := range dbPolicies {
			erp = policy.PGCreate(ctx)
			if erp != nil {
				ers := *erp
				e["acl:Policy:PGCreate"] = e["acl:GetRole"]
				e["acl:Policy:PGCreate"].Err(ctx, ers["acl:Policy:PGcreate"].Wrapper)
				return &e
			}
		}
	}
	return nil
}

func UpdateResources(ctx context.Context, resources acl.Resources) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:UpdateResource")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "UpdateResources", "")
	dbResourcesPtr, erp := acl.FindResources(ctx)
	if erp != nil {
		ers := *erp
		e["acl:FindResources"] = e["controller:UpdateResources"]
		e["acl:FindResources"].Err(ctx, ers["acl:FindResources"].Wrapper)
		return &e
	}
	if dbResourcesPtr == nil {
		e["acl:FindResources"] = e["controller:UpdateResources"]
		e["acl:FindResources"].Err(ctx, fmt.Errorf("resources is nil"))
		return &e
	}
	dbResources := *dbResourcesPtr
	oldLen := len(dbResources)
	for _, outer := range resources {
		for _, inner := range dbResources {
			if outer.URL == inner.URL {
				continue
			}
		}
		dbResources = append(dbResources, outer)
	}
	newLen := len(dbResources)
	if oldLen != newLen {
		for _, r := range dbResources {
			erp = r.PGCreate(ctx)
			if erp != nil {
				ers := *erp
				e["acl:Resource:PGCreate"] = e["controller:UpdateResources"]
				e["acl:Resource:PGCreate"].Err(ctx, ers["acl:Resource:PGCreate"].Wrapper)
				return &e
			}
		}
	}
	return nil
}

func GetContentIdFromUrl(ctx context.Context, c echo.Context) (string,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:GetContentIdFromUrl")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "GetContentIdFromUrl", "")

	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	url := c.Request().RequestURI
	segments := strings.Split(url, "/")
	if r.Match([]byte(segments[len(segments)-1])) {
		return segments[len(segments)-1], nil
	}
	e["controller:GetContentIdFromUrl"].Err(ctx, fmt.Errorf("content id not found in url"))
	return "", &e
}

func AuthenticateToken(ctx context.Context, c echo.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:AuthenticateToken")
	}
	e := errors.Error{}.New(ctx, "common.go", "controller", "AuthenticateToken", "")
	data, erp := authenticateToken(ctx, c)
	if erp != nil {
		ers := *erp
		e["controller:AuthenticateToken"].Err(ctx, ers["controller:authenticateToken"].Wrapper)
		return nil, &e
	}
	if token, ok := data["Token"].(string); ok {
		claims, erp := acl.DecodeJWT(ctx, token, []byte("secret"))
		if erp != nil {
			ers := *erp
			e["acl:DecodeJWT"] = e["controller:AuthenticateToken"]
			e["acl:DecodeJWT"].Err(ctx, ers["acl:DecodeJWT"].Wrapper)
			return nil, &e
		}
		data["claims"] = claims
		userPtr, erp := acl.GetUser(ctx, claims)
		if erp != nil {
			ers := *erp
			e["acl:GetUser"] = e["controller:AuthenticateToken"]
			e["acl:GetUser"].Err(ctx, ers["acl:GetUser"].Wrapper)
			return nil, &e
		}
		if userPtr == nil {
			e["controller:AuthenticateToken"].Err(ctx, fmt.Errorf("user is nil"))
			return nil, &e
		}
		user := *userPtr
		data["User"] = user
	}
	return data, nil
}
