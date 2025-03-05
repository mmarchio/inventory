package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/types"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LocationController struct{
	Error errors.Error
	Ctx context.Context
}

func (s LocationController) Get() echo.HandlerFunc {
	return func (c echo.Context) error {
		if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
			s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:Get")
		}
		s.Error.Function = "Get"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := AuthenticateToken(s.Ctx, c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if user, ok := data["User"].(types.User); ok {
			c.Set("user", user.Id)
			data["Authenticated"] = true
			data["User"] = user
			locationsPtr, err := types.Locations{}.FindAll(s.Ctx)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if locationsPtr == nil {
				data["error"] = fmt.Errorf("locations is nil")
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			locations := *locationsPtr
			data["Locations"] = locations
			if token, ok := data["Token"].(string); ok {
				c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			}
			return c.Render(http.StatusOK, "content.locations.tpl.html", data)
		}
		err = fmt.Errorf("invalid token")
		s.Error.Err(s.Ctx, err)
		data["error"] = err.Error()
		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (s LocationController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
			s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:GetCreate")
		}
		s.Error.Function = "GetCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			user, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			data["User"] = user
		}
		return c.Render(http.StatusOK, "content.location.create.tpl.html", data)
	}
}

func (s LocationController) GetEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
			s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:GetEdit")
		}
		s.Error.Function = "GetEdit"
		s.Error.RequestUri = c.Request().RequestURI
	
		data, err := AuthenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(s.Ctx, token, []byte("secret"))
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			userPtr, err := acl.GetUser(s.Ctx, claims)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, err.Error())
			}
			if userPtr == nil {
				err = fmt.Errorf("user pointer is nil")
				s.Error.Err(s.Ctx, err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			user := *userPtr
			data["User"] = user
			contentId, err := GetContentIdFromUrl(s.Ctx, c)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}

			contentPtr, err := types.GetContent(s.Ctx, contentId)
			if err != nil {
				data["error"] = err.Error()
				s.Error.Err(s.Ctx, err)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if contentPtr == nil {
				err = fmt.Errorf("content pointer is nil")
				s.Error.Err(s.Ctx, err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			content := *contentPtr
			location := types.Location{}

			err = json.Unmarshal(content.Content, &location)
			data["Location"] = location
			c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
		}
		return c.Render(http.StatusOK, "content.location.edit.tpl.html", data)
	}
}

func (s LocationController) GetDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
			s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:GetDelete")
		}
		s.Error.Function = "GetDelete"
		s.Error.RequestUri = c.Request().RequestURI

		data, err := AuthenticateToken(s.Ctx, c)
		if err != nil {
			data["error"] = err.Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if user, ok := data["User"].(types.User); ok {
			data["User"] = user
			l := types.Location{}
			l.Attributes.Id = c.Param("id")
			err = l.PGDelete(s.Ctx)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.locations.tpl.html", data)
	}
}

func (s LocationController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
			s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:PostApiCreate")
		}
		s.Error.Function = "PostApiCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := AuthenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			return c.JSON(http.StatusInternalServerError, err.Error())
		}

		if user, ok := data["User"].(types.User); ok {
			l := types.Location{}
			locationPtr, err := l.HydrateFromRequest(s.Ctx, c, user)
			if s.Error.ErrOrNil(s.Ctx, locationPtr, err) != nil {
				return c.JSON(http.StatusInternalServerError, data)
			}
			location := *locationPtr
			err = location.PGCreate(s.Ctx)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				data["error"] = err.Error()
				c.JSON(http.StatusInternalServerError, data)
			}
			return c.JSON(http.StatusCreated, location.Attributes.Id)
		}
		err = fmt.Errorf("invalid token")
		data["error"] = err.Error()
		s.Error.Err(s.Ctx, err)
		return c.JSON(http.StatusBadRequest, data)
	}
}

func (s LocationController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
			s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:PostApiEdit")
		}
		s.Error.Function = "PostApiEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := AuthenticateToken(s.Ctx, c)
		if err != nil {
			s.Error.Err(s.Ctx, err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		if user, ok := data["User"].(types.User); ok {
			l := types.Location{}
			locationPtr, err := l.HydrateFromRequest(s.Ctx, c, user)
			if s.Error.ErrOrNil(s.Ctx, locationPtr, err) != nil {
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			newLocation := *locationPtr

			oldLocationPtr, err := l.Load(s.Ctx, c, user)
			if s.Error.ErrOrNil(s.Ctx, oldLocationPtr, err) != nil {
				return c.JSON(http.StatusInternalServerError, err.Error())
			}
			oldLocation := *oldLocationPtr
	
			updatedLocationPtr, err := newLocation.Merge(s.Ctx, oldLocation, newLocation, user)
			if s.Error.ErrOrNil(s.Ctx, updatedLocationPtr, err) != nil {
				return c.JSON(http.StatusInternalServerError, err.Error())
			}

			updatedLocation := *updatedLocationPtr
			err = updatedLocation.PGUpdate(s.Ctx)
			if err != nil {
				s.Error.Err(s.Ctx, err)
				data["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			data["id"] = updatedLocation.Attributes.Id
			return c.JSON(204, data)
		}
		err = fmt.Errorf("invalid token")
		s.Error.Err(s.Ctx, err)
		data["error"] = err.Error()
		return c.JSON(http.StatusInternalServerError, data)
	}
}

func (s LocationController) RegisterResources(e *echo.Echo) error {
	if v, ok := s.Ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
		s.Ctx = v(s.Ctx, "stack", "controllers:location.go:LocationController:RegisterResources")
	}
	s.Error.Function = "GetCreate"

	view := e.Group("/content/location")
	api := e.Group("/api/content/location")

	e.GET("/content/locations", s.Get())
	
	view.GET("/create", s.GetCreate())
	view.GET("/edit/:id", s.GetEdit())
	view.GET("/delete/:id", s.GetDelete())

	api.POST("/create", s.PostApiCreate())
	api.POST("/edit/:id", s.PostApiEdit())

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
	adminRolePtr, err := acl.GetRole(s.Ctx, "admin")
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(s.Ctx, adminRole.Id, resources)
		if err != nil {
			return s.Error.Err(s.Ctx, err)
		}
	}
	err = UpdateResources(s.Ctx, resources)
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	err = UpdatePolicy(s.Ctx, "admin", resources)
	if err != nil {
		return s.Error.Err(s.Ctx, err)
	}
	return nil
}
