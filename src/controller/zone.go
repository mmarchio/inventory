package controller

import (
	"inventory/src/acl"
	"inventory/src/errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ZoneController struct{
	Error errors.Error
}

func (s ZoneController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
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
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ZoneController) GetEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
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
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ZoneController) GetDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
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
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s ZoneController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			s.Error.Err(err)
			data["PageTitle"] = "Inventory Management"
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["User"] = user
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (s ZoneController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["User"] = user
		}
		return c.JSON(http.StatusOK, data)
	}
}

func (c ZoneController) RegisterResources(e *echo.Echo) error {
	c.Error.Function = "RegisterResources"

	view := e.Group("/content/zone")
	api := e.Group("/api/content/zone")
	view.GET("/create", c.GetCreate())
	view.GET("/edit/:id", c.GetEdit())
	view.GET("/delete/:id", c.GetDelete())
	api.POST("/create", c.PostApiCreate())
	api.POST("/edit/:id", c.PostApiEdit())
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
		return c.Error.Err(err)
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			return c.Error.Err(err)
		}
	}
	err = UpdateResources(resources)
	if err != nil {
		return c.Error.Err(err)
	}
	err = UpdatePolicy("admin", resources)
	if err != nil {
		return c.Error.Err(err)
	}
	return nil
}
