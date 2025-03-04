package types

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/labstack/echo/v4"
)

type Location struct {
	Attributes Attributes `json:"attributes"`
	Rooms      Rooms      `json:"rooms"`
	Address    Address    `json:"address"`
}

func (c Location) New(ctx context.Context) (*Location, error) {
	attributesPtr, err := c.Attributes.New(ctx)
	if err != nil {
		return nil, err
	}
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes is nil")
	}
	location := c
	location.Attributes = *attributesPtr
	location.Attributes.ContentType = "location"
	return &location, nil
}

func (c Location) ToContent(ctx context.Context) (*Content, error) {
	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Location) PGRead(ctx context.Context) (*Location, error) {
	content, err := Content{}.Read(ctx, c.Attributes.Id)
	if err != nil {
		return nil, err
	}
	location := c
	err = json.Unmarshal(content.Content, &location)
	if err != nil {
		return nil, err
	}
	return &location, nil
}

func (c Location) PGCreate(ctx context.Context) error {
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		return err
	}
	if contentPtr == nil {
		return fmt.Errorf("content is nil")
	}
	content := *contentPtr

	return content.Create(ctx, c)
}

func (c Location) PGUpdate(ctx context.Context) error {
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		return err
	}
	if contentPtr == nil {
		return fmt.Errorf("content is nil")
	}
	content := *contentPtr
	
	return content.Update(ctx, c)
}

func (c Location) PGDelete(ctx context.Context) error {
	return Content{}.Delete(ctx, c.Attributes.Id)
}

func NewLocation(ctx context.Context, createdBy User) *Location {
	r := Location{}
	a := NewAttributes(ctx, &createdBy)
	if a != nil {
		r.Attributes = *a
	}
	return &r
}

func (c Location) IsDocument(ctx context.Context) bool {
	return true
}

func (c Location) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	return toMSI(ctx, c)
}

func (c Location) Hydrate(ctx context.Context, msi map[string]interface{}, user User) (*Location, error) {
	r := Location{}
	if a, ok := msi["attributes"].(map[string]interface{}); ok {
		r.Attributes.MSIHydrate(ctx, a)
	}
	if v, ok := msi["rooms"].([]map[string]interface{}); ok {
		roomsPtr, err := r.Rooms.Hydrate(ctx, v)
		if err != nil {
			return nil, err
		}
		if roomsPtr != nil {
			rooms := *roomsPtr
			r.Rooms = rooms
		}
	}
	a, err := r.Address.Hydrate(ctx, msi)
	if err != nil {
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

func (c Location) HydrateFromRequest(ctx context.Context, e echo.Context, user User) (*Location, error) {
	bodyPtr, err := GetRequestData(ctx, e)
	if err != nil {
		return nil, err
	}
	if bodyPtr == nil {
		err = fmt.Errorf("request body nil")
		return nil, err
	}
	body := *bodyPtr
	locationPtr, err := c.Hydrate(ctx, body, user)
	if err != nil {
		return nil, err
	}
	if locationPtr == nil {
		err = fmt.Errorf("location is nil")
		return nil, err
	}
	return locationPtr, nil
}

func (c Location) Load(ctx context.Context, e echo.Context, user User) (*Location, error) {
	contentId, err := GetContentIdFromUrl(ctx, e)
	if err != nil {
		return nil, err
	}
	contentPtr, err := GetContent(ctx, contentId)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		return nil, err
	}
	content := *contentPtr
	location := c
	err = json.Unmarshal(content.Content, &location)
	if err != nil {
		return nil, err
	}
	return &location, nil
}

func (c Location) Merge(ctx context.Context, oldInput, newInput interface{}, user User) (*Location, error) {
	var old, new Location
	if o, ok := oldInput.(map[string]interface{}); ok {
		ptr, err := c.Hydrate(ctx, o, user)
		if err != nil {
			return nil, err
		}
		old = *ptr
	}
	if o, ok := newInput.(map[string]interface{}); ok {
		ptr, err := c.Hydrate(ctx, o, user)
		if err != nil {
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
		return nil, err
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes pointer is nil")
		return nil, err
	}
	c.Attributes = *attributesPtr

	addressPtr, err := c.Address.Merge(ctx, old.Address, new.Address)
	if err != nil {
		return nil, err
	}
	if addressPtr == nil {
		err = fmt.Errorf("merged address is nil")
		return nil, err
	}
	c.Address = *addressPtr

	return &c, nil
}

func GetRequestData(ctx context.Context, c echo.Context) (*map[string]interface{}, error) {
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		return nil, err
	}
	return &body, nil
}

type Locations []Location

func (c Locations) IsDocument(ctx context.Context) bool {
	return true
}

func (c Locations) FindAll(ctx context.Context) (*Locations, error) {
	content, err := Content{}.FindAll(ctx, "location")
	if err != nil {
		return nil, err
	}
	if content == nil {
		return nil, err
	}
	locations := c 
	for _, cont := range content {
		location := Location{}
		err = json.Unmarshal(cont.Content, &location)
		if err != nil {
			return nil, err
		}
		locations = append(locations, location)
	}
	return &locations, nil
}

func (c Locations) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	return toMSI(ctx, c)
}

func (c Locations) Hydrate(ctx context.Context, msi []map[string]interface{}, user User) (*Locations, error) {
	locations := Locations{}
	for _, r := range msi {
		location := Location{}
		locationPtr, err := location.Hydrate(ctx, r, user)
		if err != nil {
			logger.Printf("%#v", err)
			return nil, err
		}
		if locationPtr != nil {
			locations = append(locations, *locationPtr)
		}
	}
	return &locations, nil
}

func (c Locations) In(ctx context.Context, id string) bool {
	for _, l := range c {
		if l.Attributes.Id == id {
			return true
		}
	}
	return false
}

func GetLocations(ctx context.Context) (*Locations, error) {
	return Locations{}.FindAll(ctx)
}