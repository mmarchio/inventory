package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/types"
	"log"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags | log.Lshortfile)

type Permission struct {
	Name string `json:"name"`
	Value bool `json:"value"`
}

type Permissions []Permission

func FindPermissions(ctx context.Context) (*Permissions, error) {
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