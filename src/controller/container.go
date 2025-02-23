package controller

import (
	"inventory/src/acl"
	"inventory/src/errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ContainerController struct{}

func (c ContainerController) GetCreate() echo.HandlerFunc {
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
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ContainerController) GetEdit() echo.HandlerFunc {
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
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ContainerController) GetDelete() echo.HandlerFunc {
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
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := getUser(claims)
			if err != nil {
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ContainerController) PostApiCreate() echo.HandlerFunc {
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

func (c ContainerController) PostApiEdit() echo.HandlerFunc {
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

func (c ContainerController) RegisterResources(e *echo.Echo) error {
	view := e.Group("/content/container")
	api := e.Group("/api/content/container")
	view.GET("/create", c.GetCreate())
	view.GET("/edit/:id", c.GetEdit())
	view.GET("/delete/:id", c.GetDelete())
	api.POST("/create", c.PostApiCreate())
	api.POST("/edit/:id", c.PostApiEdit())

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
