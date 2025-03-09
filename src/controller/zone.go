package controller

import (
	"context"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/util"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ZoneController struct {
	Errors map[string]errors.Error
	Ctx   context.Context
}

func (s ZoneController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:zone.go:ZoneController:GetCreate")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "zone.go", "controller", "GetCreate", "ZoneController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			if token != "" {
				//do something
			}
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ZoneController) GetEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:zone.go:ZoneController:GetEdit")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "zone.go", "controller", "GetEdit", "ZoneController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			if token != "" {
				//do something
			}
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ZoneController) GetDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:zone.go:ZoneController:GetDelete")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "zone.go", "controller", "GetDelete", "ZoneController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			if token != "" {
				//do something
			}
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ZoneController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:zone.go:ZoneController:PostApiCreate")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "zone.go", "controller", "PostApiCreate", "ZoneController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["PageTitle"] = "Inventory Management"
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			if token != "" {
				//do something
			}
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (s ZoneController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:zone.go:ZoneController:PostApiEdit")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "zone.go", "controller", "PostApiEdit", "ZoneController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			if token != "" {
				//do something
			}
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (s ZoneController) RegisterResources(e *echo.Echo) *map[string]errors.Error {

	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:zone.go:ZoneController:RegisterResources")
	}

	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "zone.go", "controller", "RegisterResources", "ZoneController")
	er := s.Errors[idx]
	s.Errors[idx] = er

	view := e.Group("/content/zone")
	api := e.Group("/api/content/zone")
	view.GET("/create", s.GetCreate())
	view.GET("/edit/:id", s.GetEdit())
	view.GET("/delete/:id", s.GetDelete())
	api.POST("/create", s.PostApiCreate())
	api.POST("/edit/:id", s.PostApiEdit())
	resources := acl.Resources{}
	res := acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/zone/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/zone/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/zone/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/api/zone/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/api/zone/edit",
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
