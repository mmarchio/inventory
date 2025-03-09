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

func DecodeJWT(ctx context.Context, tokenString string, secretKey []byte) (jwt.MapClaims,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:DecodeJWT")
	}
	e := errors.Error{}.New(ctx, "acl.go", "acl", "DecodeJWT", "")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err2 := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			e["acl:DecodeJWT"].Err(ctx, err2)
			return nil, err2
		}
		return secretKey, nil
	})

	if err != nil {
		e["acl:DecodeJWT"].Err(ctx, err)
		return nil, &e
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	err = fmt.Errorf("invalid token")
	e["acl:DecodeJWT"].Err(ctx, err)
	return nil, &e
}

func GetUsableClaims(ctx context.Context, c echo.Context) (*map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:GetUsableClaims")
	}
	e := errors.Error{}.New(ctx, "acl.go", "acl", "DecodeJWT", "")
	token, erp := GetBearerToken(ctx, c)
	if erp != nil {
		ers := *erp
		e["acl:GetBearerToken"] = e["acl:GetUsableClaims"]
		e["acl:GetBearerToken"].Err(ctx, ers["acl:GetBearerToken"].Wrapper)
		return nil, &e
	}
	jwt, erp := DecodeJWT(ctx, token, []byte("secret"))
	if erp != nil {
		ers := *erp
		e["acl:DecodeJWT"] = e["acl:GetUsableClaims"]
		e["acl:DecodeJWT"].Err(ctx, ers["acl:DecodeJWT"].Wrapper)
		return nil, &e
	}
	msi := make(map[string]interface{})
	b, err := json.Marshal(jwt)
	if err != nil {
		e["json:Marshal"] = e["acl:GetUsableClaims"]
		e["json:Marshal"].Err(ctx, err)
		return nil, &e
	}
	err = json.Unmarshal(b, &msi)
	if err != nil {
		e["json:Unmarshal"] = e["acl:GetUsableClaims"]
		e["json:Unmarshal"].Err(ctx, err)
		return nil, &e
	}
	return &msi, nil
}

func PermissionsHandler(ctx context.Context, c echo.Context, p Policy) (bool,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:middleware.go:PermissionsHandler")
	}
	e := errors.Error{}.New(ctx, "acl.go", "acl", "PermissionsHandler", "")
	userPtr, erp := GetUserFromContext(ctx, c)
	if erp != nil {
		ers := *erp
		e["acl:GetUserFromContext"] = e["acl:PermissionsHandler"]
		e["acl:GetUserFromContext"].Err(ctx, ers["acl:GetUserFromContext"].Wrapper)
		return false, &e
	}
	if userPtr == nil {
		err := fmt.Errorf("user is nil")
		e["acl:PermissionsHandler"].Err(ctx, err)
		return false, &e
	}

	user := *userPtr
	segments := strings.Split(c.Request().RequestURI, "/")
	contentId := segments[len(segments)-1]
	contentPtr, erp := types.GetContent(ctx, contentId)
	if erp != nil {
		ers := *erp
		e["types:GetContent"] = e["acl:PermissionsHandler"]
		e["types:GetContent"].Err(ctx, ers["types:GetContent"].Wrapper)
		return false, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content pointer is nil")
		e["acl:PermissionsHandler"].Err(ctx, err)
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
	e := errors.Error{}.New(ctx, "acl.go", "acl", "getResourcePolicy", "")
	policiesPtr, erp := Policies{}.FindPolicies(ctx)
	if erp != nil {
		ers := *erp
		e["acl:Policies:FindPolicies"] = e["acl:getResourcePolicy"]
		e["acl:Policies:FindPolicies"].Err(ctx, ers["acl:Policies:FindPolicies"].Wrapper)
		return nil, &e
	}
	if policiesPtr == nil {
		err := fmt.Errorf("policies is nil")
		e["acl:getResourcePolicy"].Err(ctx, err)
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
	e["acl:getResourcePolicy"].Err(ctx, err)
	return nil, &e
}

