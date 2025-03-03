package controller

import (
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type DashboardController struct {
	Logger *log.Logger
	Error errors.Error
}

func (s DashboardController) Get() echo.HandlerFunc {
	return func (c echo.Context) error {
		s.Error.Function = "Get"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			fmt.Printf("\nauthenticateToken err: %s\n", err.Error())
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
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
		s.Error.Err(err)
		data["error"] = err.Error()

		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (c DashboardController) RegisterResources(e *echo.Echo) error {
	c.Error.Function = "GetCreate"
	
	g := e.Group("")
	g.GET("/dashboard", c.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/dashboard",
	})
	adminRolePtr, err := acl.GetRole("admin")
	if err != nil {
		c.Error.Err(err)
		return err
	}
	if adminRolePtr != nil {
		adminRole := *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			c.Error.Err(err)
			return err
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