package controller

import (
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
		claims, err := acl.DecodeJWT(token, []byte("secret"))
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		user, err := acl.GetUser(claims)
		if err != nil {
			s.Error.Err(err)
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

func (c IndexController) RegisterResources(e *echo.Echo) error {
	c.Error.Function = "GetCreate"
	g := e.Group("")
	g.GET("/", c.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/",
	})
	adminRolePtr, err := acl.GetRole("admin")
	if err != nil {
		c.Error.Err(err)
		return err
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			if err.Error() != "roles not found" {
				c.Error.Err(err)
				return err
			}
		}
	}
	err = UpdateResources(resources)
	if err != nil {
		c.Error.Err(err)
		return err
	}
	err = UpdatePolicy("admin", resources)
	if err != nil {
		c.Error.Err(err)
		return err
	}
	return nil
}