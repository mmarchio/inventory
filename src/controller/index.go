package controller

import (
	"context"
	"inventory/src/acl"
	"inventory/src/errors"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type IndexController struct {
	Logger *log.Logger
	Error errors.Error
	Ctx context.Context
}

func (s IndexController) Get() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "Get"
		s.Error.RequestUri = c.Request().RequestURI

		data := make(map[string]interface{})
		data["PageTitle"] = "Inventory Management"
		bearer := c.Request().Header.Get("AUTHORIZATION")
		if bearer == "" {
			data["Authenticated"] = false
			return c.Render(http.StatusOK, "index.tpl.html", data)
		}
		token := strings.Split(bearer, " ")[1]
		claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		user, err := acl.GetUser(s.Ctx, claims)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		c.Set("user", user.Id)
		c.Response().Header().Set("AUTHORIZATION", bearer)
		data["Authenticated"] = true
		data["Token"] = token
		return c.Render(http.StatusOK, "dashboard.tpl.html", data)
	}
}

func (s IndexController) RegisterResources(e *echo.Echo) error {
	s.Error.Function = "GetCreate"
	g := e.Group("")
	g.GET("/", s.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/",
	})
	adminRolePtr, err := acl.GetRole(s.Ctx, "admin")
	if err != nil {
		s.Error.Err(s.Ctx, err)
		return err
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(s.Ctx, adminRole.Id, resources)
		if err != nil {
			if err.Error() != "roles not found" {
				s.Error.Err(s.Ctx, err)
				return err
			}
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