package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/types"
	"strings"

	"github.com/labstack/echo/v4"
)

type Permission struct {
	Name string `json:"name"`
	Value bool `json:"value"`
}

type Permissions []Permission

func FindPermissions(ctx context.Context) (*Permissions, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl.go:FindPermissions")
	}
	content, err := types.Content{}.FindAll(ctx, "permission")
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

func GetBearerToken(ctx context.Context, c echo.Context) (string, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl.go:FindPermissions")
	}
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

func GetUserFromContext(ctx context.Context, c echo.Context) (*types.User, error) {
	if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		ctx = v(ctx, "stack", "acl.go:FindPermissions")
	}
	token, err := GetBearerToken(ctx, c)
	if err != nil {
		return nil, err
	}
	jwt, err := DecodeJWT(ctx, token, []byte("secret"))
	if err != nil {
		return nil, err
	}
	userPtr, err := GetUser(ctx, jwt)
	if err != nil {
		return nil, err
	}
	return userPtr, nil
}