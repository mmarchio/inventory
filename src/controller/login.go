package controller

import (
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/db"
	"inventory/src/errors"
	"inventory/src/login"
	"inventory/src/types"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LoginController struct{
	Error errors.Error
}

func (c LoginController) RegisterResources(e *echo.Echo) error {
	c.Error.Function = "RegisterResources"

	e.GET("", c.LogoutHandler())
	e.POST("", c.ApiLoginHandler())

	resources := acl.Resources{}
	res := acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/login",
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

func (s LoginController) LogoutHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := make(map[string]interface{})
		bearer := c.Request().Header.Get("AUTHORIZATION")
		if bearer == "" {
			data["Authenticated"] = false
			return c.Render(http.StatusOK, "index.tpl.html", data)
		}
		token := strings.Split(bearer, " ")[1]
		_, err := acl.DecodeJWT(token, []byte("secret"))
		if err != nil {
			return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
		}
		return c.Render(http.StatusOK, "index.tpl.html", nil)
	}
}

func (s LoginController) ApiLoginHandler() echo.HandlerFunc{
	return func(c echo.Context) error {
		s.Error.Function = "ApiLoginHandler"
		s.Error.RequestUri = c.Request().RequestURI
		msg := make(map[string]interface{})
		redis, err := db.NewRedisClient()
		if err != nil {
			s.Error.Err(err)
			msg["error"] = fmt.Sprintf("redis: %s", err.Error())
			return c.JSON(http.StatusInternalServerError, msg)
		}
		requestBody, err := GetRequestData(c) 
		if err != nil {
			s.Error.Err(err)
			msg["error"] = fmt.Sprintf("json: %s", err.Error())
		}
		if requestBody == nil {
			msg["error"] = "request body empty"
			return c.JSON(http.StatusBadRequest, msg)
		}
		body := *requestBody
		creds := login.Credentials{}
		if v, ok := body["username"].(string); ok {
			creds.Username = v
		}
		if v, ok := body["password"].(string); ok {
			creds.Password = v
		}
		res, err := redis.ReadJSONDocument("auth", ".")
		if err != nil {
			s.Error.Err(err)
			msg["error"] = fmt.Sprintf("redis: %s", err.Error())
			return c.JSON(http.StatusInternalServerError, msg)
		}
		var jsonRes string
		if res != nil {
			jsonRes = *res
		}
		if jsonRes[0] != '[' {
			jsonRes = fmt.Sprintf("[%s]", jsonRes)
		}
		users := types.Users{}
		err = json.Unmarshal([]byte(jsonRes), &users)
		if err != nil {
			s.Error.Err(err)
			msg["error"] = fmt.Sprintf("json: %s", err.Error())
			msg["input"] = jsonRes
			return c.JSON(http.StatusInternalServerError, msg)
		}
	
		for _, u := range users {
			if u.Username == creds.Username {
				auth, err := login.Login(u.Username, creds.Password, u.Password)
				if err != nil {
					s.Error.Err(err)
					msg["error"] = fmt.Sprintf("auth: %s", err.Error())
					return c.JSON(http.StatusInternalServerError, msg)
				}
				if auth != nil {
					c.SetCookie(auth)
					c.Set("Authenticated", true)
					c.Set("user", u)
					c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", auth.Value))
					msg["authenticated"] = true
					msg["token"] = auth.Value;
					return c.JSON(http.StatusOK, msg)
				}
			}
		}
	
		msg["error"] = "user not found"
		return c.JSON(http.StatusNotFound, msg)
	}
}

