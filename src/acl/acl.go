package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
	"strings"

	"github.com/labstack/echo/v4"
)

var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type Permission struct {
	Name string `json:"name"`
	Value bool `json:"value"`
}

type Permissions []Permission

func FindPermissions(ctx context.Context) (*Permissions, error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl.go:FindPermissions")
	}
	e := errors.Error{
		Package: "acl",
		Function: "FindPermissions",
	}
	content, err := types.Content{}.FindAll(ctx, "permission")
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	r := Permissions{}
	for _, c := range content {
		permission := Permission{}
		err = json.Unmarshal(c.Content, &permission)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		r = append(r, permission)
	}
	return &r, nil
}

func GetBearerToken(ctx context.Context, c echo.Context) (string, error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl.go:FindPermissions")
	}
	e := errors.Error{
		Package: "acl",
		Function: "GetBearerToken",
	}
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		err := fmt.Errorf("authorization header not found")
		e.Err(ctx, err)
		return "", err
	}
	parts := strings.Split(bearer, " ")
	if len(parts) != 2 {
		err := fmt.Errorf("unexpected authorization header segments")
		e.Err(ctx, err)
		return "", err
	}
	return parts[1], nil
}

func GetUserFromContext(ctx context.Context, c echo.Context) (*types.User, error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:acl.go:GetUserFromContext")
	}
	e := errors.Error{
		Package: "acl",
		Function: "GetBearerToken",
	}
	token, err := GetBearerToken(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	jwt, err := DecodeJWT(ctx, token, []byte("secret"))
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	userPtr, err := GetUser(ctx, jwt)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return userPtr, nil
}