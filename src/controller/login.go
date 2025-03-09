package controller

import (
	"context"
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/login"
	"inventory/src/types"
	"inventory/src/util"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LoginController struct {
	Errors map[string]errors.Error
	Ctx   context.Context
}

func (s LoginController) RegisterResources(e *echo.Echo) *map[string]errors.Error {

	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:login.go:LoginController:RegisterResources")
	}

	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "login.go", "controller", "RegisterResources", "LoginController")
	er := s.Errors[idx]
	s.Errors[idx] = er

	e.GET("/logout", s.LogoutHandler())
	e.POST("/api/login", s.ApiLoginHandler())

	resources := acl.Resources{}
	res := acl.Resource{
		Id:  uuid.NewString(),
		URL: "/api/login",
	}
	resources = append(resources, res)

	params := acl.Role{}
	params.Attributes.Name = "admin"
	adminRolePtr, erp := acl.GetRole(s.Ctx, params)
	if erp != nil {
		fidx := "acl:GetRole"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		erp = UpdateRole(s.Ctx, adminRole.Attributes.Id, resources)
		if erp != nil {
			fidx := "controller:UpdateRole"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			return &s.Errors
		}
	}
	erp = UpdateResources(s.Ctx, resources)
	if erp != nil {
		fidx := "controller:UpdateResources"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}
	erp = UpdatePolicy(s.Ctx, "admin", resources)
	if erp != nil {
		fidx := "controller:UpdatePolicy"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}
	return nil
}

func (s LoginController) LogoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:login.go:LoginController:LogoutHandler")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "login.go", "controller", "LogoutHandler", "LoginController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := authenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		domain := os.Getenv("APP_DOMAIN")
		if domain == "" {
			err := fmt.Errorf("app domain not found")
			fidx := "os:Getenv"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}

		cookie := &http.Cookie{
			Domain:  domain,
			Expires: time.Now(),
		}
		c.SetCookie(cookie)
		data["Authenticated"] = false
		return c.Render(http.StatusOK, "index.tpl.html", nil)
	}
}

func (s LoginController) ApiLoginHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:login.go:LoginController:ApiLoginHandler")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "login.go", "controller", "ApiLoginHandler", "LoginController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		msg := make(map[string]interface{})
		requestBody, erp := GetRequestData(s.Ctx, c)
		if erp != nil {
			fidx := "controller:GetRequestData"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			msg["error"] = s.Errors[fidx].Error()
			return c.JSON(http.StatusInternalServerError, msg)
		}
		if requestBody == nil {
			err := fmt.Errorf("request body nil")
			fidx := "controller:GetRequestData"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
			msg["error"] = err.Error()
			return c.JSON(http.StatusBadRequest, msg)
		}
		body := *requestBody
		creds := login.Credentials{}
		if v, ok := body["username"].(string); ok {
			creds.Username = v
		}
		if v, ok := body["password"].(string); ok {
			creds.Password = v
		}
		jstring := fmt.Sprintf("{\"username\":\"%s\"}", creds.Username)
		authPtr, erp := login.Credentials{}.FindBy(s.Ctx, jstring)
		if erp != nil {
			fidx := "login:Credentials:FindBy"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			msg["error"] = s.Errors[fidx].Error()
			return c.JSON(http.StatusBadRequest, msg)
		}
		if authPtr == nil {
			fidx := "login:Credentials:FindBy"
			err := fmt.Errorf("auth ptr is nil")
			errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
			msg["error"] = err.Error()
			return c.JSON(http.StatusBadRequest, msg)
		}
		dbCreds := *authPtr
		auth, erp := login.Login(s.Ctx, creds.Username, creds.Password, dbCreds.Password)
		if erp != nil {
			fidx := "login:Login"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			msg["error"] = s.Errors[fidx].Error()
			return c.JSON(http.StatusInternalServerError, msg)
		}
		if auth != nil {
			fidx := "login:Login"
			userPtr, erp := types.User{}.FindBy(s.Ctx, jstring)
			if erp != nil {
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				msg["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, msg)
			}
			if userPtr == nil {
				fidx := "login:Login"
				err := fmt.Errorf("user point is nil")
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				msg["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, msg)
			}
			c.SetCookie(auth)
			c.Set("Authenticated", true)
			c.Set("user", *userPtr)
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", auth.Value))
			msg["authenticated"] = true
			msg["token"] = auth.Value
			return c.JSON(http.StatusOK, msg)
		}
		msg["error"] = "user not found"
		return c.JSON(http.StatusNotFound, msg)
	}
}
