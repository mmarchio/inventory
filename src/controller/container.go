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

type ContainerController struct{
	Error errors.Error
	Ctx context.Context
}

func (s ContainerController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:GetCreate")
		}
		s.Error.Function = "GetCreate"
		s.Error.RequestUri = c.Request().RequestURI

		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
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
		s.Error.Function = "GetEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
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
		s.Error.Function = "GetDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
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
		s.Error.Function = "PostApiCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["User"] = user
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (s ContainerController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:PostApiEdit")
		}
		s.Error.Function = "PostApiEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["User"] = user
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (s ContainerController) RegisterResources(e *echo.Echo) error {
	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:container.go:ContainerController:RegisterResources")
	}
	s.Error.Function = "RegisterResources"

	view := e.Group("/content/container")
	api := e.Group("/api/content/container")
	view.GET("/create", s.GetCreate())
	view.GET("/edit/:id", s.GetEdit())
	view.GET("/delete/:id", s.GetDelete())
	api.POST("/create", s.PostApiCreate())
	api.POST("/edit/:id", s.PostApiEdit())

	resources := acl.Resources{}
	res := acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/container/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/container/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/container/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/container/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/container/edit",
	}
	resources = append(resources, res)

	adminRolePtr, err := acl.GetRole(s.Ctx, "admin")
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(s.Ctx, adminRole.Id, resources)
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
