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
	s.Error.Function = "RegisterResources"

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
	adminRolePtr, err := acl.GetRole(s.Ctx, params)
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(s.Ctx, adminRole.Attributes.Id, resources)
		if err != nil {
			return s.Error.Err(s.Ctx, err)
		}
	}
	err = UpdateResources(s.Ctx, resources)
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	err = UpdatePolicy(s.Ctx, "admin", resources)
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	return nil
}

func (s LoginController) LogoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:login.go:LoginController:LogoutHandler")
		}
		s.Error.Function = "LogoutHandler"

		data := make(map[string]interface{})
		bearer := c.Request().Header.Get("AUTHORIZATION")
		if bearer == "" {
			data["Authenticated"] = false
			return c.Render(http.StatusOK, "index.tpl.html", data)
		}
		domain := os.Getenv("APP_DOMAIN")
		if domain == "" {
			err := fmt.Errorf("app domain not found")
			s.Error.Err(s.Ctx, err)
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
		fmt.Println("loginController:ApiLoginHandler")
		s.Error.Function = "ApiLoginHandler"
		s.Error.RequestUri = c.Request().RequestURI
		msg := make(map[string]interface{})
		requestBody, err := GetRequestData(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			msg["error"] = fmt.Sprintf("json: %s", err.Error())
		}
		if requestBody == nil {
			msg["error"] = "request body empty"
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
		authPtr, err := login.Credentials{}.FindBy(s.Ctx, jstring)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			msg["error"] = err.Error()
			return c.JSON(http.StatusBadRequest, msg)
		}
		if authPtr == nil {
			err = fmt.Errorf("auth ptr is nil")
			s.Error.Err(s.Ctx, err)
			msg["error"] = err.Error()
			return c.JSON(http.StatusBadRequest, msg)
		}
		dbCreds := *authPtr
		auth, err := login.Login(s.Ctx, creds.Username, creds.Password, dbCreds.Password)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			msg["error"] = fmt.Sprintf("redis: %s", err.Error())
			return c.JSON(http.StatusInternalServerError, msg)
		}
		if auth != nil {
			userPtr, err := types.User{}.FindBy(s.Ctx, jstring)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				msg["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, msg)
			}
			if userPtr == nil {
				err := fmt.Errorf("user point is nil")
				s.Error.Err(s.Ctx, err)
				msg["error"] = fmt.Sprintf("redis: %s", err.Error())
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
