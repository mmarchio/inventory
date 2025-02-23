package controller

import (
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/db"
	"inventory/src/errors"
	"inventory/src/types"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type RoomController struct {}

func (c RoomController) GetRoomCreate() echo.HandlerFunc {
	
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
		return c.Render(http.StatusOK, "content.room.create.tpl.html", data)
	}
}

func (cl RoomController) GetRoomEdit() echo.HandlerFunc {
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
			redis, err := db.NewRedisClient()
			if err != nil {
				errors.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)

			}
			redisResponseString, err := redis.ReadJSONDocument("content", ".")
			if err != nil {
				errors.Err(err)
				data["error"] = err.Error()
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
						errors.Err(err)
						data["error"] = err.Error()
						return c.Render(http.StatusInternalServerError, ERRORTPL, data)
					}
					data["Locations"] = locations
				}
			}
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "content.locations.tpl.html", data)
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (c RoomController) GetRoomDelete() echo.HandlerFunc {
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

func (c RoomController) PostApiRoomCreate() echo.HandlerFunc {
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

func (c RoomController) PostApiRoomEdit() echo.HandlerFunc {
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

func (c RoomController) RegisterResources(e *echo.Echo) error {
	view := e.Group("/content/room")
	api := e.Group("/api/content/room")

	view.GET("/create", c.GetRoomCreate())
	view.GET("/edit/:id", c.GetRoomEdit())
	view.GET("/delete/:id", c.GetRoomDelete())
	api.POST("/create", c.PostApiRoomCreate())
	api.POST("/edit/:id", c.PostApiRoomEdit())

	resources := acl.Resources{}
	res := acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/room/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/room/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/room/delete",
	}
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/room/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/content/api/room/edit",
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
