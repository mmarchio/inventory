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

type ContainerController struct {
	Errors map[string]errors.Error
	Ctx   context.Context
}

func (s ContainerController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:GetCreate")
		}
		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "container.go", "controller", "GetCreate", "ContainerController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Wrapper
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, erp := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if erp != nil {
				fidx := "acl:DecodeJWT"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", s.Errors[fidx].Wrapper)
			}
			user, erp := acl.GetUser(s.Ctx, claims)
			if erp != nil {
				fidx := "acl:GetUser"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", s.Errors[fidx].Wrapper)
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ContainerController) GetEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:GetEdit")
		}
		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "container.go", "controller", "GetEdit", "ContainerController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er


		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Wrapper
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, erp := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if erp != nil {
				fidx := "acl:DecodeJWT"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", s.Errors[fidx].Wrapper)
			}
			user, erp := acl.GetUser(s.Ctx, claims)
			if erp != nil {
				fidx := "acl:GetUser"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", s.Errors[fidx].Wrapper)
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ContainerController) GetDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:GetDelete")
		}
		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "container.go", "controller", "GetDelete", "ContainerController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Wrapper
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

func (s ContainerController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:PostApiCreate")
		}
		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "container.go", "controller", "PostApiCreate", "ContainerController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Wrapper
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

func (s ContainerController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:PostApiEdit")
		}
		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "container.go", "controller", "PostApiEdit", "ContainerController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Wrapper
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

func (s ContainerController) RegisterResources(e *echo.Echo) *map[string]errors.Error {
	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:RegisterResources")
	}
	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "container.go", "controller", "RegisterResources", "ContainerController")
	er := s.Errors[idx]
	s.Errors[idx] = er


	view := e.Group("/content/container")
	api := e.Group("/api/content/container")
	view.GET("/create", s.GetCreate())
	view.GET("/edit/:id", s.GetEdit())
	view.GET("/delete/:id", s.GetDelete())
	api.POST("/create", s.PostApiCreate())
	api.POST("/edit/:id", s.PostApiEdit())

	resources := acl.Resources{}
	res := acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/container/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/container/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/container/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/api/container/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/api/container/edit",
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
