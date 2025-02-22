package controller

import (
	"fmt"
	"inventory/src/acl"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type DashboardController struct {
	Logger *log.Logger
}

func (c DashboardController) Get() echo.HandlerFunc {
	return func (c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			fmt.Printf("\nauthenticateToken err: %s\n", err.Error())
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			c.Set("user", user.Id)
			data["Authenticated"] = true
			data["Token"] = token
			data["User"] = user
			data["PageTitle"] = "Inventory Management"
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "dashboard.tpl.html", data)
		}
		fmt.Printf("\ndata: %#v\n", data)
		data["error"] = "invalid token"
		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (c DashboardController) RegisterResources(e *echo.Echo) error {
	g := e.Group("")
	g.GET("/dashboard", c.Get())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/dashboard",
	})
	adminRolePtr, err := acl.GetRole("admin")
	if err != nil {
		return err
	}
	if adminRolePtr != nil {
		adminRole := *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			return err
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