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
	Errors map[string]errors.Error
	Ctx    context.Context
}

func (s DashboardController) Get() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:dashboard.go:DashboardController:Get")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "dashboard.go", "controller", "GetCreate", "DashboardController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			ers := *erp
			fidx := "controller:AuthenticateToken"
			if ers[fidx].Error() == "bearer not found" {
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = ers[fidx].Error()
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if token, ok := data["Token"].(string); ok {
			c.Set("user", data["user"])
			data["Authenticated"] = true
			data["PageTitle"] = "Inventory Management"
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "dashboard.tpl.html", data)
		}
		err := fmt.Errorf("invalid token")
		s.Errors[idx].Err(s.Ctx, err)
		data["error"] = err.Error()

		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (s DashboardController) RegisterResources(e *echo.Echo) *map[string]errors.Error {
	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:dashboard.go:DashboardController:RegisterResources")
	}
	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "dashboard.go", "controller", "RegisterResources", "DashboardController")
	er := s.Errors[idx]
	s.Errors[idx] = er

	g := e.Group("")
	g.GET("/dashboard", s.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id:  uuid.NewString(),
		URL: "/dashboard",
	})
	params := acl.Role{}
	params.Attributes.Name = "admin"
	adminRolePtr, erp := acl.GetRole(s.Ctx, params)
	if erp != nil {
		fidx := "acl:GetRole"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}
	if adminRolePtr != nil {
		adminRole := *adminRolePtr
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
