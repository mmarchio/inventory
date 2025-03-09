package acl

import (
	"context"
	"fmt"
	"inventory/src/errors"
	// "inventory/src/types"
	"inventory/src/util"
	"os"
	"regexp"

	// "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type IDocument interface {
	IsDocument() bool
	ToMSI() (map[string]interface{}, *map[string]errors.Error)
}

func ACL(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := context.Background()
		if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			ctx = v(ctx, ckey, "acl:middleware.go:ACL")
		}
		e := errors.Error{}.New(ctx, "middleware.go", "acl", "ACL", "")
		if err := next(c); err != nil {
			e["acl:ACL"].Err(ctx, err)
			c.Error(err)
		}
		if skipper(c) {
			return nil
		}
		token, erp := GetBearerToken(ctx, c)
		if erp != nil {
			ers := *erp
			e["acl:GetBearerToken"] = e["acl:ACL"]
			e["acl:GetBearerToken"].Err(ctx, ers["acl:GetBearerToken"].Wrapper)
			return ers["acl:GetBearerToken"].Wrapper
		}
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			err := fmt.Errorf("secret not found")
			e["acl:ACL"].Err(ctx, err)
		}
		// if authorization[len(authorization)-2:len(authorization)-1] != "==" {
		// 	authorization = fmt.Sprintf("%s==", authorization)
		// }

		claims, erp := DecodeJWT(ctx, token, []byte("secret"))
		if erp != nil {
			ers := *erp
			e["acl:DecodeJWT"] = e["acl:ACL"]
			e["acl:DecodeJWT"].Err(ctx, ers["acl:DecodeJWT"])
			return ers["acl:DecodeJWT"].Wrapper
		}
		user, erp := GetUser(ctx, claims)
		if erp != nil {
			ers := *erp
			e["acl:GetUser"] = e["acl:ACL"]
			e["acl:GetUser"].Err(ctx, ers["acl:GetUser"].Wrapper)
			return ers["acl:GetUser"].Wrapper
		}
		if user != nil {
			us := *user
			policyPtr, erp := getResourcePolicy(ctx, us, c.Request().URL.Path)
			if erp != nil {
				ers := *erp
				e["acl:getResourcePolicy"] = e["acl:ACL"]
				e["acl:getResourcePolicy"].Err(ctx, ers["acl:getResourcePolicy"].Wrapper)
				return ers["acl:getResourcePolicy"].Wrapper
			}
			if policyPtr == nil {
				err := fmt.Errorf("policy is nil")
				e["acl:ACL"].Err(ctx, err)
				return err
			}
			policy := *policyPtr
			if policy.IsContent {
				auth, erp := PermissionsHandler(ctx, c, policy)
				if erp != nil {
					ers := *erp
					e["acl:PermissionsHandler"] = e["acl:ACL"]
					e["acl:PermissionsHandler"].Err(ctx, ers["acl:PermissionsHandler"].Wrapper)
					return ers["acl:PermissionsHandler"].Wrapper
				}
				if auth {
					return nil
				} else {
					err := fmt.Errorf("access forbidden")
					e["acl:ACL"].Err(ctx, err)
					return err
				}
			}
		}
		return nil
	}
}


func skipper(c echo.Context) bool {
	pattern := regexp.QuoteMeta(".js") + "|" + regexp.QuoteMeta(".css") + "|" + regexp.QuoteMeta("logout") + "|" + regexp.QuoteMeta("login")
	r := regexp.MustCompile(pattern)
	if c.Request().URL.Path == "" || c.Request().URL.Path == "/" || r.Match([]byte(c.Request().URL.Path)) {
		return true
	}
	return false
}


