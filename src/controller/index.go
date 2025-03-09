package controller

import (
	"context"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type IndexController struct {
	Logger *log.Logger
	Errors map[string]errors.Error
	Ctx    context.Context
}

func (s IndexController) Get() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:index.go:IndexController:Get")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "index.go", "controller", "Get", "IndexController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			return c.Render(http.StatusOK, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if user, ok := data["User"].(types.User); ok {
			c.Set("user", user.Attributes.Id)
		}
		var bearer string
		if v, ok := data["bearer"].(string); ok {
			bearer = v
		}
		c.Response().Header().Set("AUTHORIZATION", bearer)
		data["Authenticated"] = true
		return c.Render(http.StatusOK, "dashboard.tpl.html", data)
	}
}

func (s IndexController) RegisterResources(e *echo.Echo) *map[string]errors.Error {
	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:index.go:IndexController:RegisterResources")
	}
	
	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "index.go", "controller", "RegisterResources", "IndexController")
	er := s.Errors[idx]
	s.Errors[idx] = er
	
	g := e.Group("")
	g.GET("/", s.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id:  uuid.NewString(),
		URL: "/",
	})
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
			if s.Errors[fidx].Error() != "roles not found" {
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				return &s.Errors
			}
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
