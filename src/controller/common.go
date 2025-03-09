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

func GetRequestData(ctx context.Context, c echo.Context) (*map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:GetRequestData")
	}
	e := errors.Error{}
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &body, nil
}

func authenticateToken(ctx context.Context, c echo.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:authenticateToken")
	}
	e := errors.Error{}
	data := make(map[string]interface{})
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		data["Authenticated"] = false
		return data, fmt.Errorf("bearer not found")
	}
	bearerParts := strings.Split(bearer, " ")
	var token string
	if len(bearerParts) > 1 {
		token = bearerParts[1]
	}
	data["Token"] = token
	_, err := acl.DecodeJWT(ctx, token, []byte("secret"))
	if err != nil {
		e.Err(ctx, err)
		data["error"] = err.Error()
		return data, err
	}
	tokenPtr, err := login.ExtendToken(ctx, token, []byte("secret"))
	if err != nil {
		e.Err(ctx, err)
		return data, err
	}
	if tokenPtr != nil {
		data["Token"] = token
	}
	data["Authenticated"] = true
	return data, nil
}

func CreatePolicy(ctx context.Context, resource, role, permission string) (*acl.Policy,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:CreatePolicy")
	}
	e := errors.Error{}
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
	e.Err(ctx, err)
	return nil, err
}

func UpdateRole(ctx context.Context, id string, resources acl.Resources) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:UpdateRole")
	}
	e := errors.Error{}
	params := acl.Role{}
	params.Attributes.Id = id
	rolePtr, err := acl.GetRole(ctx, params)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	var role acl.Role
	if rolePtr != nil {
		role = *rolePtr
	}
	for _, resource := range resources {
		polPtr, err := CreatePolicy(ctx, resource.URL, role.Attributes.Name, role.DefaultPermisison)
		if err != nil || polPtr == nil {
			e.Err(ctx, err)
			return err
		}
		role.Policies = append(role.Policies, *polPtr)
	}
	err = role.PGCreate(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func UpdatePolicy(ctx context.Context, role string, resources acl.Resources) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:UpdatePolicy")
	}
	e := errors.Error{}
	dbPoliciesPtr, err := acl.GetPolicyByRole(ctx, role)
	if err != nil {
		e.Err(ctx, err)
		return err
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
			rolePtr, err := acl.GetRole(ctx, params)
			if err != nil {
				e.Err(ctx, err)
				return err
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
			err = policy.PGCreate(ctx)
			if err != nil {
				e.Err(ctx, err)
				return err
			}
		}
	}
	return nil
}

func UpdateResources(ctx context.Context, resources acl.Resources) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:UpdateResource")
	}
	e := errors.Error{}
	dbResourcesPtr, err := acl.FindResources(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if dbResourcesPtr == nil {
		err = fmt.Errorf("resources is nil")
		e.Err(ctx, err)
		return err
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
			err = r.PGCreate(ctx)
			if err != nil {
				e.Err(ctx, err)
				return err
			}
		}
	}
	return nil
}

func GetContentIdFromUrl(ctx context.Context, c echo.Context) (string,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:GetContentIdFromUrl")
	}
	e := errors.Error{}
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	url := c.Request().RequestURI
	segments := strings.Split(url, "/")
	if r.Match([]byte(segments[len(segments)-1])) {
		return segments[len(segments)-1], nil
	}
	err := fmt.Errorf("content id not found in url")
	e.Err(ctx, err)
	return "", err
}

func AuthenticateToken(ctx context.Context, c echo.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "controllers:common.go:AuthenticateToken")
	}
	e := errors.Error{}
	data, err := authenticateToken(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if token, ok := data["Token"].(string); ok {
		claims, err := acl.DecodeJWT(ctx, token, []byte("secret"))
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		data["claims"] = claims
		userPtr, err := acl.GetUser(ctx, claims)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if userPtr == nil {
			err = fmt.Errorf("user is nil")
			e.Err(ctx, err)
			return nil, err
		}
		user := *userPtr
		data["User"] = user
	}
	return data, nil
}
