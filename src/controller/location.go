package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LocationController struct {
	Errors map[string]errors.Error
	Ctx   context.Context
}

func (s LocationController) Get() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:Get")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "Get", "LocationController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			ers := *erp
			fidx := "controller:AuthenticateToken"
			data["PageTitle"] = "Inventory Management"
			if ers[fidx].Error() == "bearer not found" {
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if user, ok := data["User"].(types.User); ok {
			c.Set("user", user.Id)
			data["Authenticated"] = true
			data["User"] = user
			locationsPtr, erp := types.Locations{}.FindAll(s.Ctx)
			if erp != nil {
				fidx := "types:Locations:FindAll"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if locationsPtr == nil {
				err := fmt.Errorf("locations is nil")
				fidx := "types:Locations:FindAll"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			locations := *locationsPtr
			data["Locations"] = locations
			if token, ok := data["Token"].(string); ok {
				c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", token))
			}
			return c.Render(http.StatusOK, "content.locations.tpl.html", data)
		}
		err := fmt.Errorf("invalid token")
		s.Errors[idx].Err(s.Ctx, err)
		data["error"] = err.Error()
		return c.Render(http.StatusInternalServerError, ERRORTPL, data)
	}
}

func (s LocationController) GetCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:GetCreate")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "GetCreate", "LocationController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			if token != "" {
				//do something
			}
		}
		return c.Render(http.StatusOK, "content.location.create.tpl.html", data)
	}
}

func (s LocationController) GetEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:GetEdit")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "GetEdit", "LocationController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:Authenticate"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			contentId, erp := GetContentIdFromUrl(s.Ctx, c)
			if erp != nil {
				fidx := "controller:GetContentIdFromUrl"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}

			contentPtr, erp := types.GetContent(s.Ctx, contentId)
			if erp != nil {
				fidx := "types:GetContent"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if contentPtr == nil {
				err := fmt.Errorf("content pointer is nil")
				fidx := "types:GetContent"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			content := *contentPtr
			location := types.Location{}

			err := json.Unmarshal(content.Content, &location)
			if err != nil {
				fidx := "json:Unmarshal"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
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
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:GetDelete")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "GetDelete", "LocationController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			data["PageTitle"] = "Inventory Management"
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if user, ok := data["User"].(types.User); ok {
			data["User"] = user
			l := types.Location{}
			l.Attributes.Id = c.Param("id")
			erp = l.PGDelete(s.Ctx)
			if erp != nil {
				fidx := "types:Location:PGDelete"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "content.locations.tpl.html", data)
	}
}

func (s LocationController) PostApiCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:PostApiCreate")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "PostApiCreate", "LocationController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			return c.JSON(http.StatusInternalServerError, data)
		}

		if user, ok := data["User"].(types.User); ok {
			l := types.Location{}
			locationPtr, erp := l.HydrateFromRequest(s.Ctx, c, user)
			if erp != nil {
				fidx := "types:Location:HydrateFromRequest"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			if locationPtr == nil {
				err := fmt.Errorf("location pointer is nil")
				fidx := "types:Location:HydrateFromRequest"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			location := *locationPtr
			erp = location.PGCreate(s.Ctx)
			if erp != nil {
				fidx := "types:Location:PGCreate"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				c.JSON(http.StatusInternalServerError, data)
			}
			return c.JSON(http.StatusCreated, location.Attributes.Id)
		}
		err := fmt.Errorf("invalid token")
		s.Errors[idx].Err(s.Ctx, err)		
		data["error"] = err.Error()
		return c.JSON(http.StatusBadRequest, data)
	}
}

func (s LocationController) PostApiEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
			s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:PostApiEdit")
		}

		var idx string
		s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "PostApiEdit", "LocationController")
		er := s.Errors[idx]
		er.RequestUri = c.Request().RequestURI
		s.Errors[idx] = er

		data, erp := AuthenticateToken(s.Ctx, c)
		if erp != nil {
			fidx := "controller:AuthenticateToken"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			data["error"] = s.Errors[fidx].Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if user, ok := data["User"].(types.User); ok {
			l := types.Location{}
			locationPtr, erp := l.HydrateFromRequest(s.Ctx, c, user)
			if erp != nil {
				fidx := "types:Location:HydrateFromRequest"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			if locationPtr == nil {
				err := fmt.Errorf("location pointer is nil")
				fidx := "types:Location:HydrateFromRequest"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				data["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			newLocation := *locationPtr

			oldLocationPtr, erp := l.Load(s.Ctx, c, user)
			if erp != nil {
				fidx := "types:Location:Load"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			if oldLocationPtr == nil {
				err := fmt.Errorf("old location pointer is nil")
				fidx := "types:Location:Load"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				data["error"] = err.Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			oldLocation := *oldLocationPtr

			updatedLocationPtr, erp := newLocation.Merge(s.Ctx, oldLocation, newLocation, user)
			if erp != nil {
				fidx := "types:Location:Merge"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			if updatedLocationPtr == nil {
				err := fmt.Errorf("updated location pointer is nil")
				fidx := "types:Location:Merge"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}

			updatedLocation := *updatedLocationPtr
			erp = updatedLocation.PGUpdate(s.Ctx)
			if erp != nil {
				fidx := "types:Location:PGUpdate"
				errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
				data["error"] = s.Errors[fidx].Error()
				return c.JSON(http.StatusInternalServerError, data)
			}
			data["id"] = updatedLocation.Attributes.Id
			return c.JSON(204, data)
		}
		err := fmt.Errorf("invalid token")
		s.Errors[idx].Err(s.Ctx, err)
		data["error"] = err.Error()
		return c.JSON(http.StatusInternalServerError, data)
	}
}

func (s LocationController) RegisterResources(e *echo.Echo) *map[string]errors.Error {

	if v, ok := s.Ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		s.Ctx = v(s.Ctx, ckey, "controllers:location.go:LocationController:RegisterResources")
	}

	var idx string
	s.Errors, idx = errors.Error{}.New(s.Ctx, "location.go", "controller", "RegisterResources", "LocationController")
	er := s.Errors[idx]
	s.Errors[idx] = er

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
		Id:  uuid.NewString(),
		URL: "/content/locations",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/location/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/location/edit",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/content/location/delete",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/api/content/location/create",
	}
	resources = append(resources, res)
	res = acl.Resource{
		Id:  uuid.NewString(),
		URL: "/api/content/location/edit",
	}
	resources = append(resources, res)
	params := acl.Role{}
	params.Attributes.Name = "admin"
	adminRolePtr, erp := acl.GetRole(s.Ctx, params)
	if erp != nil {
		fidx := "acl:GetRole"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}

	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		erp = UpdateRole(s.Ctx, adminRole.Attributes.Id, resources)
		if erp != nil {
			fidx := "controller:UpdateRole"
			errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
			return &s.Errors
		}
	} else {
		fidx := "acl:GetRole"
		err := fmt.Errorf("admin role pointer is nil")
		errors.CreateErrorEntry(s.Ctx, idx, fidx, nil, err, &s.Errors)
		return &s.Errors
	}
	erp = UpdateResources(s.Ctx, resources)
	if erp != nil {
		fidx := "controller:UpdateResources"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}
	erp = UpdatePolicy(s.Ctx, "admin", resources)
	if erp != nil {
		fidx := "controller:UpdatePolicy"
		errors.CreateErrorEntry(s.Ctx, idx, fidx, erp, nil, &s.Errors)
		return &s.Errors
	}
	return nil
}
