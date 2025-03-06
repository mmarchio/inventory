package controller

import (
	"context"
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/util"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type DashboardController struct {
	Logger *log.Logger
	Error errors.Error
	Ctx context.Context
}

func (s DashboardController) Get() echo.HandlerFunc {
	return func (c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:dashboard.go:DashboardController:Get")
		}
		s.Error.Function = "Get"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			if err.Error() == "bearer not found" {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			fmt.Printf("\nauthenticateToken err: %s\n", err.Error())
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			c.Set("user", user.Id)
			data["Authenticated"] = true
			data["Token"] = token
			data["User"] = user
			data["PageTitle"] = "Inventory Management"
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "dashboard.tpl.html", data)
		}
		err = fmt.Errorf("invalid token")
		s.Error.Err(s.Ctx, err)
		data["error"] = err.Error()

		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (s DashboardController) RegisterResources(e *echo.Echo) error {
	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:dashboard.go:DashboardController:RegisterResources")
	}
	s.Error.Function = "GetCreate"
	
	g := e.Group("")
	g.GET("/dashboard", s.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/dashboard",
	})
	adminRolePtr, err := acl.GetRole(s.Ctx, "admin")
	if err != nil {
		s.Error.Err(s.Ctx, err)
		return err
	}
	if adminRolePtr != nil {
		adminRole := *adminRolePtr
		err = UpdateRole(s.Ctx, adminRole.Attributes.Id, resources)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			return err
		}
	}
	err = UpdateResources(s.Ctx, resources)
	if err != nil {
		s.Error.Err(s.Ctx, err)
		return err
	}
	err = UpdatePolicy(s.Ctx, "admin", resources)
	if err != nil {
		s.Error.Err(s.Ctx, err)
		return err
	}
	return nil
}