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

type RoomController struct {
	Errors map[string]errors.Error
	Ctx   context.Context
}

func (s RoomController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:room.go:RoomController:GetCreate")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "room.go", "controller", "GetCreate", "RoomController")
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
		return c.Render(http.StatusOK, "content.room.create.tpl.html", data)
	}
}

func (s RoomController) GetEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:room.go:RoomController:GetEdit")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "room.go", "controller", "GetEdit", "RoomController")
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

func (s RoomController) GetDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:room.go:RoomController:GetDelete")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "room.go", "controller", "GetDelete", "RoomController")
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

func (s RoomController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:room.go:RoomController:PostApiCreate")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "room.go", "controller", "PostApiCreate", "RoomController")
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

func (s RoomController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:room.go:RoomController:PostApiEdit")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "room.go", "controller", "PostApiEdit", "RoomController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := authenticateToken(s.Ctx, c)
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

func (s RoomController) RegisterResources(e *echo.Echo) *map[string]errors.Error {
	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:room.go:RoomController:RegisterResources")
	}

	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "room.go", "controller", "Get", "RoomController")
	er := s.Errors[idx]
	s.Errors[idx] = er

	view := e.Group("/content/room")
	api := e.Group("/api/content/room")

	view.GET("/create", s.GetCreate())
	view.GET("/edit/:id", s.GetEdit())
	view.GET("/delete/:id", s.GetDelete())
	api.POST("/create", s.PostApiCreate())
	api.POST("/edit/:id", s.PostApiEdit())

	resources := acl.Resources{}
	res := acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/room/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/room/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/room/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/api/room/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/api/room/edit",
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
