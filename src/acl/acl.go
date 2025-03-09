package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type Permission struct {
	Name string `json:"name"`
	Value bool `json:"value"`
}

type Permissions []Permission

func FindPermissions(ctx context.Context) (*Permissions, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl.go:FindPermissions")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "FindPermissions", "")
	content, erp := types.Content{}.FindAll(ctx, "permission")
	if erp != nil {
		ers := *erp
		fidx := "types:Content:FindAll"
		e[fidx] = e[idx]
		e[fidx].Err(ctx, ers[fidx].Wrapper)
		return nil, &e
	}
	r := Permissions{}
	for _, c := range content {
		permission := Permission{}
		err := json.Unmarshal(c.Content, &permission)
		if err != nil {
			e[idx].Err(ctx, err)
			return nil, &e
		}
		r = append(r, permission)
	}
	return &r, nil
}

func GetBearerToken(ctx context.Context, c echo.Context) (string, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl.go:FindPermissions")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "GetBearerToken", "")
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		err := fmt.Errorf("authorization header not found")
		e[idx].Err(ctx, err)
		return "", &e
	}
	parts := strings.Split(bearer, " ")
	if len(parts) != 2 {
		err := fmt.Errorf("unexpected authorization header segments")
		e[idx].Err(ctx, err)
		return "", &e
	}
	return parts[1], nil
}

func GetUser(ctx context.Context, claims jwt.MapClaims) (*types.User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:GetUser")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "GetUserFromContext", "")
	b, err := json.Marshal(claims)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	msi := make(map[string]interface{})
	err = json.Unmarshal(b, &msi)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	var jstring string
	if v, ok := msi["username"].(string); ok {
		jstring = fmt.Sprintf("{\"username\": \"%s\"}", v)
	}
	userPtr, erp := types.User{}.FindBy(ctx, jstring)
	if erp != nil {
		fidx := "types:User:FindBy"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if userPtr == nil {
		err = fmt.Errorf("user is nil")
		e[idx].Err(ctx, err)
		return nil, &e
	}
	return userPtr, nil
}

func GetUserFromContext(ctx context.Context, c echo.Context) (*types.User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:acl.go:GetUserFromContext")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "GetUserFromContext", "")
	token, erp := GetBearerToken(ctx, c)
	if erp != nil {
		fidx := "acl:GetBearerToken"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	jwt, erp := DecodeJWT(ctx, token, []byte("secret"))
	if erp != nil {
		fidx := "acl:DecodeJWT"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	userPtr, erp := GetUser(ctx, jwt)
	if erp != nil {
		fidx := "acl:GetUser"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	return userPtr, nil
}

func DecodeJWT(ctx context.Context, tokenString string, secretKey []byte) (jwt.MapClaims,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:DecodeJWT")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "DecodeJWT", "")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err2 := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			e[idx].Err(ctx, err2)
			return nil, err2
		}
		return secretKey, nil
	})

	if err != nil {
		e[idx].Err(ctx, err)
		return nil, &e
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	err = fmt.Errorf("invalid token")
	e[idx].Err(ctx, err)
	return nil, &e
}

func GetUsableClaims(ctx context.Context, c echo.Context) (*map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:GetUsableClaims")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "DecodeJWT", "")
	token, erp := GetBearerToken(ctx, c)
	if erp != nil {
		fidx := "acl:GetBearerToken"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	jwt, erp := DecodeJWT(ctx, token, []byte("secret"))
	if erp != nil {
		fidx := "acl:DecodeJWT"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	msi := make(map[string]interface{})
	b, err := json.Marshal(jwt)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	err = json.Unmarshal(b, &msi)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	return &msi, nil
}

func PermissionsHandler(ctx context.Context, c echo.Context, p Policy) (bool,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:PermissionsHandler")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "PermissionsHandler", "")
	userPtr, erp := GetUserFromContext(ctx, c)
	if erp != nil {
		fidx := "acl:GetUserFromContext"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return false, &e
	}
	if userPtr == nil {
		err := fmt.Errorf("user is nil")
		e[idx].Err(ctx, err)
		return false, &e
	}

	user := *userPtr
	segments := strings.Split(c.Request().RequestURI, "/")
	contentId := segments[len(segments)-1]
	contentPtr, erp := types.GetContent(ctx, contentId)
	if erp != nil {
		fidx := "types:GetContent"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return false, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content pointer is nil")
		e[idx].Err(ctx, err)
		return false, &e
	}
	content := *contentPtr
	if user.HasRole(ctx, p.Role) {
		switch p.Permission.Name {
		case "all":
			return true, nil
		case "created":
			if user.Attributes.Id == content.Attributes.CreatedBy {
				return true, nil
			}
		case "owned":
			if user.Attributes.Id == content.Attributes.Owner {
				return true, nil
			}
		default:
			return false, nil
		}
	}
	return false, &e
}

func pathToResource(ctx context.Context, url string) string {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:middleware.go:pathToResource")
	}
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	segments := strings.Split(url, "/")
	s := url
	if r.Match([]byte(segments[len(segments)-1])) {
		s = strings.Join(segments[0:len(segments)-1], "/")
	}
	return s
}

func getResourcePolicy(ctx context.Context, u types.User, resource string) (*Policy,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:getResourcePolicy")
	}
	e, idx := errors.Error{}.New(ctx, "acl.go", "acl", "getResourcePolicy", "")
	policiesPtr, erp := Policies{}.FindPolicies(ctx)
	if erp != nil {
		fidx := "acl:Policies:FindPolicies"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if policiesPtr == nil {
		err := fmt.Errorf("policies is nil")
		e[idx].Err(ctx, err)
		return nil, &e
	}
	policies := *policiesPtr
	for _, p := range policies {
		resource = pathToResource(ctx, resource)
		if resource == p.Resource && u.HasRole(ctx, p.Role) {
			return &p, nil
		}
	}
	err := fmt.Errorf(resource)
	e[idx].Err(ctx, err)
	return nil, &e
}

