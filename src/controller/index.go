package controller

import (
	"fmt"
	"inventory/src/acl"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type IndexController struct {
	Logger *log.Logger
}

func (c IndexController) Get() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		data["PageTitle"] = "Inventory Management"
		fmt.Println(c.Get("user"))
		bearer := c.Request().Header.Get("AUTHORIZATION")
		if bearer == "" {
			data["Authenticated"] = false
			return c.Render(http.StatusOK, "index.tpl.html", data)
		}
		token := strings.Split(bearer, " ")[1]
		claims, err := decodeJWT(token, []byte("secret"))
		if err != nil {
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, "error.tpl.html", data)
		}
		user, err := getUser(claims)
		if err != nil {
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, "error.tpl.html", data)
		}
		c.Set("user", user.Id)
		c.Response().Header().Set("AUTHORIZATION", bearer)
		data["Authenticated"] = true
		data["Token"] = token
		return c.Render(http.StatusOK, "dashboard.tpl.html", data)
	}
}

func (c IndexController) RegisterResources(e *echo.Echo) error {
	g := e.Group("")
	g.GET("/", c.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/",
	})
	adminRolePtr, err := acl.GetRole("admin")
	if err != nil {
		return err
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			if err.Error() != "roles not found" {
				return err
			}
		}
	}
	err = UpdateResources(resources)
	if err != nil {
		return err
	}
	err = UpdatePolicy("admin", resources)
	if err != nil {
		return err
	}
	return nil
}