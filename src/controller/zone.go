package controller

import (
	"inventory/src/acl"
	"inventory/src/errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ZoneController struct{}

func (c ZoneController) GetZoneCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			errors.Err(err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ZoneController) GetZoneEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			errors.Err(err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ZoneController) GetZoneDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			errors.Err(err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ZoneController) PostApiZoneCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			errors.Err(err)
			data["PageTitle"] = "Inventory Management"
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["User"] = user
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (c ZoneController) PostApiZoneEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			errors.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["User"] = user
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (c ZoneController) RegisterResources(e *echo.Echo) error {
	view := e.Group("/content/zone")
	api := e.Group("/api/content/zone")
	view.GET("/create", c.GetZoneCreate())
	view.GET("/edit/:id", c.GetZoneEdit())
	view.GET("/delete/:id", c.GetZoneDelete())
	api.POST("/create", c.PostApiZoneCreate())
	api.POST("/edit/:id", c.PostApiZoneEdit())
	resources := acl.Resources{}
	res := acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/zone/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/zone/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/zone/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/zone/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/zone/edit",
	}
	resources = append(resources, res)
	adminRolePtr, err := acl.GetRole("admin")
	if err != nil {
		return errors.Err(err)
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			return errors.Err(err)
		}
	}
	err = UpdateResources(resources)
	if err != nil {
		return errors.Err(err)
	}
	err = UpdatePolicy("admin", resources)
	if err != nil {
		return errors.Err(err)
	}
	return nil
}
