package controller

import (
	//	"encoding/json"
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/db"
	"inventory/src/errors"
	"inventory/src/types"
	"log"

	//	"inventory/src/db"
	//	"inventory/src/login"
	//	"inventory/src/types"
	"net/http"
	//	"strings"
	//	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ContentController struct {
	Logger *log.Logger
}

func (c ContentController) RegisterResources(e *echo.Echo) error {
	view := e.Group("/content")
	view.GET("/locations", c.Get())
	view.GET("/item/create", c.GetItemCreate())
	view.GET("/item/edit/:id", c.GetItemEdit())
	view.GET("/item/delete/:id", c.GetItemDelete())


	resources := acl.Resources{}
	res := acl.Resource{}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/item/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/item/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/item/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/item/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/item/edit",
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

func (cl ContentController) Get() echo.HandlerFunc {
	return func (c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				errors.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			fmt.Printf("\nauthenticateToken err: %s\n", err.Error())
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := decodeJWT(token, []byte("secret"))
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			userPtr, err := getUser(claims)
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if userPtr == nil {
				data["error"] = fmt.Sprintf("user is nil")
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			user := *userPtr
			c.Set("user", user.Id)
			data["Authenticated"] = true
			data["Token"] = token
			data["User"] = user
			redis, err := db.NewRedisClient()
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)

			}
			redisResponseString, err := redis.ReadJSONDocument("content", ".")
			if err != nil {
				data["error"] = err.Error()
				errors.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if redisResponseString != nil {
				responseString := *redisResponseString
				if len(responseString) > 0 && responseString[0] != '[' {
					responseString = fmt.Sprintf("[%s]", responseString)
				}
				if types.JSONValidate([]byte(responseString), &types.Locations{}) {
					locations := types.Locations{}
					err = json.Unmarshal([]byte(responseString), &locations)
					if err != nil {
						data["error"] = err.Error()
						errors.Err(err)
						return c.Render(http.StatusInternalServerError, ERRORTPL, data)
					}
					data["Locations"] = locations
				}
			}
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "content.locations.tpl.html", data)
		}
		err = fmt.Errorf("invalid token")
		errors.Err(err)
		data["error"] = err.Error()
		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (c ContentController) GetItemCreate() echo.HandlerFunc {
	return func (c echo.Context) error {
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
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ContentController) GetItemEdit() echo.HandlerFunc {
	return func (c echo.Context) error {
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
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ContentController) GetItemDelete() echo.HandlerFunc {
	return func (c echo.Context) error {
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
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c ContentController) PostApiItemCreate() echo.HandlerFunc {
	return func (c echo.Context) error {
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

func (c ContentController) PostApiItemEdit() echo.HandlerFunc {
	return func (c echo.Context) error {
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
