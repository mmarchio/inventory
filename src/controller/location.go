package controller

import (
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/types"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LocationController struct{}

func (cl LocationController) GetLocationCreate() echo.HandlerFunc {
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
		return c.Render(http.StatusOK, "content.location.create.tpl.html", data)
	}
}

func (cl LocationController) GetLocationEdit() echo.HandlerFunc {
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
			contentId, err := GetContentIdFromUrl(c)
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}

			msiPtr, err := types.GetContent(contentId)
			if err != nil {
				if err != nil {
					data["error"] = err.Error()
					errors.Err(err)
					return c.Render(http.StatusInternalServerError, ERRORTPL, data)
				}
			}
			if msiPtr != nil {
				err = fmt.Errorf("content pointer is nil")
				errors.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "content.room.edit.tpl.html", data)
		}
		return c.Render(http.StatusOK, "content.room.edit.tpl.html", data)
	}
}

func (cl LocationController) GetLocationDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
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
		return c.Render(http.StatusOK, "content.locations.tpl.html", data)
	}
}

func (cl LocationController) PostApiLocationCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			data["error"] = err.Error()
			errors.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			userPtr, err := getUser(claims)
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			if userPtr == nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.JSON(http.StatusBadRequest, data)
			}
			user := *userPtr
			data["User"] = user
			bodyPtr, err := GetRequestData(c)
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			if bodyPtr == nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.JSON(http.StatusBadRequest, data)
			}
			body := *bodyPtr
			locations := types.Locations{}
			r, err := locations.MergeLocations(body, user)
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			return c.JSON(http.StatusCreated, r)
		}
		data["error"] = err.Error()
		errors.Err(err)
		return c.JSON(http.StatusBadRequest, data)
	}
}

func (cl LocationController) PostApiLocationEdit() echo.HandlerFunc {
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

func (c LocationController) RegisterResources(e *echo.Echo) error {
	view := e.Group("/content/location")
	api := e.Group("/api/content/location")

	view.GET("/location/create", c.GetLocationCreate())
	view.GET("/location/edit/:id", c.GetLocationEdit())
	view.GET("/location/delete/:id", c.GetLocationDelete())

	api.POST("/location/create", c.PostApiLocationCreate())
	api.POST("/location/edit/:id", c.PostApiLocationEdit())

	resources := acl.Resources{}

	res := acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/locations",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/location/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/location/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/location/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/location/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/location/edit",
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
