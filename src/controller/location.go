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

type LocationController struct{
	Error errors.Error
}

func (s LocationController) Get() echo.HandlerFunc {
	return func (c echo.Context) error {
		s.Error.Function = "Get"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			userPtr, err := getUser(claims)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if userPtr == nil {
				data["error"] = "user is nil"
				s.Error.Err(err)
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
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)

			}
			redisResponseString, err := redis.ReadJSONDocument("content", ".")
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
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
						s.Error.Err(err)
						return c.Render(http.StatusInternalServerError, ERRORTPL, data)
					}
					data["Locations"] = locations
				}
			}
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "content.locations.tpl.html", data)
		}
		err = fmt.Errorf("invalid token")
		s.Error.Err(err)
		data["error"] = err.Error()
		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (s LocationController) GetCreate() echo.HandlerFunc {
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
			user, err := getUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			data["User"] = user
		}
		return c.Render(http.StatusOK, "content.location.create.tpl.html", data)
	}
}

func (s LocationController) GetEdit() echo.HandlerFunc {
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
			userPtr, err := getUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			if userPtr == nil {
				err = fmt.Errorf("user pointer is nil")
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			user := *userPtr
			data["User"] = user
			contentId, err := GetContentIdFromUrl(c)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}

			msiPtr, err := types.GetContent(contentId)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if msiPtr == nil {
				err = fmt.Errorf("content pointer is nil")
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			msi := *msiPtr
			l := types.Location{}
			
			location, err := l.Hydrate(msi, user)
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			data["Location"] = location
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
		}
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s LocationController) GetDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetDelete"
		s.Error.RequestUri = c.Request().RequestURI

		data, err := authenticateToken(c)
		if err != nil {
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
			user, err := getUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			data["User"] = user
			locations := types.Locations{}
			redis, err := db.NewRedisClient()
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			redisResponseString, err := redis.ReadJSONDocument("content", ".")
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if redisResponseString == nil {
				err = fmt.Errorf("redis response is nil")
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			responseString := *redisResponseString
			if len(responseString) > 0 && responseString != "" && responseString != " " {
				if responseString[0] != '[' {
					responseString = fmt.Sprintf("[%s]", responseString)
				}
				err = json.Unmarshal([]byte(responseString), &locations)
				if err != nil {
					s.Error.Err(err)
					data["error"] = err.Error()
					return c.Render(http.StatusInternalServerError, ERRORTPL, data)
				}
				newLocations := types.Locations{}
				for _, l := range locations {
					if l.Attributes.Id == c.Param("id") {
						continue
					} 
					newLocations = append(newLocations, l)
				}
				err = redis.CreateJSONDocument(newLocations, "content", ".", true)
				if err != nil {
					s.Error.Err(err)
					data["error"] = err.Error()
					return c.Render(http.StatusInternalServerError, ERRORTPL, data)
				}
			}
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.locations.tpl.html", data)
	}
}

func (s LocationController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["error"] = err.Error()
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			userPtr, err := getUser(claims)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			if userPtr == nil {
				err = fmt.Errorf("user pointer is nil")
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.JSON(http.StatusBadRequest, data)
			}
			user := *userPtr
			data["User"] = user
			bodyPtr, err := GetRequestData(c)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, data)
			}
			if bodyPtr == nil {
				err = fmt.Errorf("body pointer is nil")
				data["error"] = err.Error()
				s.Error.Err(err)
				return c.JSON(http.StatusBadRequest, data)
			}
			body := *bodyPtr
			locations := types.Locations{}
			l := types.Location{}
			locationPtr, err := l.Hydrate(body, user)
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			if locationPtr == nil {
				err = fmt.Errorf("location is nil")
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			location := *locationPtr

			redis, err := db.NewRedisClient()
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				c.JSON(http.StatusInternalServerError, data)
			}
			redisResponseString, err := redis.ReadJSONDocument("content", ".")
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				c.JSON(http.StatusInternalServerError, data)
			}
			if redisResponseString == nil {
				err = fmt.Errorf("redis response is nil")
				s.Error.Err(err)
				data["error"] = err.Error()
				c.JSON(http.StatusInternalServerError, data)
			}
			responseString := *redisResponseString
			if len(responseString) > 0 && responseString[0] != '[' {
				responseString = fmt.Sprintf("[%s]", responseString)
			}
			err = json.Unmarshal([]byte(responseString), &locations)
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				c.JSON(http.StatusInternalServerError, data)
			}
			locations = append(locations, location)
			err = redis.CreateJSONDocument(locations, "content", ".", true)
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				c.JSON(http.StatusInternalServerError, data)
			}

			return c.JSON(http.StatusCreated, location.Attributes.Id)
		}
		err = fmt.Errorf("invalid token")
		data["error"] = err.Error()
		s.Error.Err(err)
		return c.JSON(http.StatusBadRequest, data)
	}
}

func (s LocationController) PostApiEdit() echo.HandlerFunc {
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
			userPtr, err := getUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			if userPtr == nil {
				err = fmt.Errorf("user is nil")
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			user := *userPtr
			data["User"] = user
			bodyPtr, err := GetRequestData(c)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			if bodyPtr == nil {
				err = fmt.Errorf("request body nil")
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			l := types.Location{}
			locationPtr, err := l.Hydrate(*bodyPtr, user)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			if locationPtr == nil {
				err = fmt.Errorf("location is nil")
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}

			contentId, err := GetContentIdFromUrl(c)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			contentPtr, err := types.GetContent(contentId)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			if contentPtr == nil {
				err = fmt.Errorf("content is nil")
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			content := *contentPtr
			ls := types.Locations{}
			id, err := ls.MergeLocations(content, user)
			if err != nil {
				s.Error.Err(err)
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			data["id"] = id
			return c.JSON(http.StatusOK, data)
		}
		err = fmt.Errorf("invalid token")
		s.Error.Err(err)
		data["error"] = err.Error()
		return c.JSON(http.StatusInternalServerError, data)
	}
}

func (c LocationController) RegisterResources(e *echo.Echo) error {
	c.Error.Function = "GetCreate"

	view := e.Group("/content/location")
	api := e.Group("/api/content/location")

	e.GET("/content/locations", c.Get())
	
	view.GET("/create", c.GetCreate())
	view.GET("/edit/:id", c.GetEdit())
	view.GET("/delete/:id", c.GetDelete())

	api.POST("/create", c.PostApiCreate())
	api.POST("/edit/:id", c.PostApiEdit())

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
		URL: "/api/content/location/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/content/location/edit",
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
