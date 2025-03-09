package types

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/util"

	"github.com/labstack/echo/v4"
)

type Location struct {
	Attributes Attributes `json:"attributes"`
	Rooms      Rooms      `json:"rooms"`
	Address    Address    `json:"address"`
	Error      errors.Error
}

func (c Location) New(ctx context.Context) (*Location, *errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:New")
	}
	c.Error.File = "location.go"
	c.Error.Package = "types"
	c.Error.Function = "New"
	c.Error.Struct = "Location"

	attributesPtr, err := c.Attributes.New(ctx)
	if err != nil {
		c.Error.Err(ctx, err)
		return nil, &c.Error
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		c.Error.Err(ctx, err)
		return nil, &c.Error
	}
	location := c
	location.Attributes = *attributesPtr
	location.Attributes.ContentType = "location"
	return &location, nil
}

func (c Location) ToContent(ctx context.Context) (*Content, *errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:ToContent")
	}
	c.Error.File = "location.go"
	c.Error.Package = "types"
	c.Error.Function = "ToContent"
	c.Error.Struct = "Location"

	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		c.Error.Err(ctx, err)
		return nil, &c.Error
	}
	content.Content = jbytes
	return &content, nil
}

func (c Location) PGRead(ctx context.Context) (*Location, *errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:PGRead")
	}
	c.Error.File = "location.go"
	c.Error.Package = "types"
	c.Error.Function = "PGRead"
	c.Error.Struct = "Location"

	content, err := Content{}.Read(ctx, c.Attributes.Id)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	location := c
	err = json.Unmarshal(content.Content, &location)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &location, nil
}

func (c Location) PGCreate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:PGCreate")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return err
	}
	content := *contentPtr

	err = content.Create(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Location) PGUpdate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:PGUpdate")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return err
	}
	content := *contentPtr

	err = content.Update(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Location) PGDelete(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:PGDelete")
	}
	err := Content{}.Delete(ctx, c.Attributes.Id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func NewLocation(ctx context.Context, createdBy User) *Location {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:NewLocation")
	}
	r := Location{}
	a := NewAttributes(ctx, &createdBy)
	if a != nil {
		r.Attributes = *a
	}
	return &r
}

func (c Location) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:IsDocument")
	}
	return true
}

func (c Location) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:ToMSI")
	}
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return data, nil
}

func (c Location) Hydrate(ctx context.Context, msi map[string]interface{}, user User) (*Location, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:Hydrate")
	}
	e := errors.Error{}
	r := Location{}
	if a, ok := msi["attributes"].(map[string]interface{}); ok {
		r.Attributes.MSIHydrate(ctx, a)
	}
	if v, ok := msi["rooms"].([]map[string]interface{}); ok {
		roomsPtr, err := r.Rooms.Hydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if roomsPtr != nil {
			rooms := *roomsPtr
			r.Rooms = rooms
		}
	}
	a, err := r.Address.Hydrate(ctx, msi)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if a != nil {
		r.Address = *a
		if r.Address.Attributes.Id == "" {
			addressPtr := NewAttributes(ctx, &user)
			if addressPtr != nil {
				r.Address.Attributes = *addressPtr
			}
		}
	}
	if r.Attributes.Id == "" {
		addressPtr := NewAttributes(ctx, &user)
		if addressPtr != nil {
			r.Attributes = *addressPtr
		}
	}
	if v, ok := msi["name"].(string); ok {
		r.Attributes.Name = v
	}

	return &r, nil
}

func (c Location) HydrateFromRequest(ctx context.Context, e echo.Context, user User) (*Location, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:HydrateFromRequest")
	}
	er := errors.Error{}
	bodyPtr, err := GetRequestData(ctx, e)
	if err != nil {
		er.Err(ctx, err)
		return nil, err
	}
	if bodyPtr == nil {
		err = fmt.Errorf("request body nil")
		er.Err(ctx, err)
		return nil, err
	}
	body := *bodyPtr
	locationPtr, err := c.Hydrate(ctx, body, user)
	if err != nil {
		er.Err(ctx, err)
		return nil, err
	}
	if locationPtr == nil {
		err = fmt.Errorf("location is nil")
		er.Err(ctx, err)
		return nil, err
	}
	return locationPtr, nil
}

func (c Location) Load(ctx context.Context, e echo.Context, user User) (*Location, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:Load")
	}
	er := errors.Error{}
	contentId, err := GetContentIdFromUrl(ctx, e)
	if err != nil {
		er.Err(ctx, err)
		return nil, err
	}
	contentPtr, err := GetContent(ctx, contentId)
	if err != nil {
		er.Err(ctx, err)
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		er.Err(ctx, err)
		return nil, err
	}
	content := *contentPtr
	location := c
	err = json.Unmarshal(content.Content, &location)
	if err != nil {
		er.Err(ctx, err)
		return nil, err
	}
	return &location, nil
}

func (c Location) Merge(ctx context.Context, oldInput, newInput interface{}, user User) (*Location, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Location:Merge")
	}
	e := errors.Error{}
	var old, new Location
	if o, ok := oldInput.(map[string]interface{}); ok {
		ptr, err := c.Hydrate(ctx, o, user)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		old = *ptr
	}
	if o, ok := newInput.(map[string]interface{}); ok {
		ptr, err := c.Hydrate(ctx, o, user)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		new = *ptr
	}
	if o, ok := oldInput.(Location); ok {
		old = o
	}
	if o, ok := newInput.(Location); ok {
		new = o
	}

	attributesPtr, err := c.Attributes.Merge(ctx, old.Attributes, new.Attributes)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes pointer is nil")
		e.Err(ctx, err)
		return nil, err
	}
	c.Attributes = *attributesPtr

	addressPtr, err := c.Address.Merge(ctx, old.Address, new.Address)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if addressPtr == nil {
		err = fmt.Errorf("merged address is nil")
		e.Err(ctx, err)
		return nil, err
	}
	c.Address = *addressPtr

	return &c, nil
}

func GetRequestData(ctx context.Context, c echo.Context) (*map[string]interface{}, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:GetRequestData")
	}
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return &body, nil
}

type Locations []Location

func (c Locations) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Locations:IsDocument")
	}
	return true
}

func (c Locations) FindAll(ctx context.Context) (*Locations, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Locations:FindAll")
	}
	e := errors.Error{
		Package:  "types",
		File:     "location.go",
		Struct:   "Locations",
		Function: "FindAll",
	}
	e.GetCtxTrace(ctx)
	content, err := Content{}.FindAll(ctx, "location")
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if content == nil {
		e.Err(ctx, err)
		return nil, err
	}
	locations := c
	for _, cont := range content {
		location := Location{}
		e.Wrapper = json.Unmarshal(cont.Content, &location)
		if e.Wrapper != nil {
			e.Err(ctx, e.Wrapper)
			return nil, &e
		}
		locations = append(locations, location)
	}
	return &locations, nil
}

func (c Locations) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Locations:ToMSI")
	}
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return data, nil
}

func (c Locations) Hydrate(ctx context.Context, msi []map[string]interface{}, user User) (*Locations, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Locations:Hydrate")
	}
	e := errors.Error{}
	locations := Locations{}
	for _, r := range msi {
		location := Location{}
		locationPtr, err := location.Hydrate(ctx, r, user)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if locationPtr != nil {
			locations = append(locations, *locationPtr)
		}
	}
	return &locations, nil
}

func (c Locations) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Locations:In")
	}
	for _, l := range c {
		if l.Attributes.Id == id {
			return true
		}
	}
	return false
}

func GetLocations(ctx context.Context) (*Locations, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:location.go:Locations:GetLocations")
	}
	locations, err := Locations{}.FindAll(ctx)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return locations, nil
}
