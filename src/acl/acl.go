package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
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
	e := errors.Error{}.New(ctx, "acl.go", "acl", "FindPermissions", "")
	content, erp := types.Content{}.FindAll(ctx, "permission")
	if erp != nil {
		ers := *erp
		e["types:Content:FindAll"] = e["acl:FindPermissions"]
		e["types:Content:FindAll"].Err(ctx, ers["types:Content:FindAll"].Wrapper)
		return nil, &e
	}
	r := Permissions{}
	for _, c := range content {
		permission := Permission{}
		err := json.Unmarshal(c.Content, &permission)
		if err != nil {
			e["acl:FindPermissions"].Err(ctx, err)
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
	e := errors.Error{}.New(ctx, "acl.go", "acl", "GetBearerToken", "")
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		err := fmt.Errorf("authorization header not found")
		e["acl:GetBearerToken"].Err(ctx, err)
		return "", &e
	}
	parts := strings.Split(bearer, " ")
	if len(parts) != 2 {
		err := fmt.Errorf("unexpected authorization header segments")
		e["acl:GetBearerToken"].Err(ctx, err)
		return "", &e
	}
	return parts[1], nil
}

func GetUser(ctx context.Context, claims jwt.MapClaims) (*types.User,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:GetUser")
	}
	e := errors.Error{}.New(ctx, "acl.go", "acl", "GetUserFromContext", "")
	b, err := json.Marshal(claims)
	if err != nil {
		e["json:Marshal"] = e["acl:GetUser"]
		e["json:Marshal"].Err(ctx, err)
		return nil, &e
	}
	msi := make(map[string]interface{})
	err = json.Unmarshal(b, &msi)
	if err != nil {
		e["json:Unmarshal"] = e["acl:GetUser"]
		e["json:Unmarshal"].Err(ctx, err)
		return nil, &e
	}
	var jstring string
	if v, ok := msi["username"].(string); ok {
		jstring = fmt.Sprintf("{\"username\": \"%s\"}", v)
	}
	userPtr, erp := types.User{}.FindBy(ctx, jstring)
	if erp != nil {
		ers := *erp
		e["types:User:FindBy"] = e["acl:GetUser"]
		e["types:User:FindBy"].Err(ctx, ers["types:User:FindBy"].Wrapper)
		return nil, &e
	}
	if userPtr == nil {
		err = fmt.Errorf("user is nil")
		e["acl:GetUser"].Err(ctx, err)
		return nil, &e
	}
	return userPtr, nil
}


func GetUserFromContext(ctx context.Context, c echo.Context) (*types.User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:acl.go:GetUserFromContext")
	}
	e := errors.Error{}.New(ctx, "acl.go", "acl", "GetUserFromContext", "")
	token, erp := GetBearerToken(ctx, c)
	if erp != nil {
		ers := *erp
		e["acl:GetBearerToken"] = e["acl:GetUserFromContext"]
		e["acl:GetBearerToken"].Err(ctx, ers["acl:GetBearerToken"].Wrapper)
		return nil, &e
	}
	jwt, erp := DecodeJWT(ctx, token, []byte("secret"))
	if erp != nil {
		ers := *erp
		e["acl:DecodeJWT"] = e["acl:GetUserFromContext"]
		e["acl:DecodeJWT"].Err(ctx, ers["acl:DecodeJWT"].Wrapper)
		return nil, &e
	}
	userPtr, erp := GetUser(ctx, jwt)
	if erp != nil {
		ers := *erp
		e["acl:GetUser"] = e["acl:GetUserFromContext"]
		e["acl:GetUser"].Err(ctx, ers["acl:GetUser"].Wrapper)
		return nil, &e
	}
	return userPtr, nil
}