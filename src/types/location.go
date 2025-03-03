package types

import (
	"encoding/json"
	"fmt"
	"inventory/src/db"

	"github.com/labstack/echo/v4"
)

type Location struct {
	Attributes Attributes `json:"attributes"`
	Rooms      Rooms      `json:"rooms"`
	Address    Address    `json:"address"`
}

func (c Location) New() (*Location, error) {
	attributesPtr, err := c.Attributes.New()
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

func (c Location) ToContent() (*Content, error) {
	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Location) PGRead() (*Location, error) {
	content, err := Content{}.Read(c.Attributes.Id)
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

func (c Location) PGCreate() error {
	contentPtr, err := c.ToContent()
	if err != nil {
		return err
	}
	if contentPtr == nil {
		return fmt.Errorf("content is nil")
	}
	content := *contentPtr

	return content.Create(c)
}

func (c Location) PGUpdate() error {
	contentPtr, err := c.ToContent()
	if err != nil {
		return err
	}
	if contentPtr == nil {
		return fmt.Errorf("content is nil")
	}
	content := *contentPtr
	
	return content.Update(c)
}

func (c Location) PGDelete() error {
	return Content{}.Delete(c.Attributes.Id)
}

func NewLocation(createdBy User) *Location {
	r := Location{}
	a := NewAttributes(&createdBy)
	if a != nil {
		r.Attributes = *a
	}
	return &r
}

func (c Location) IsDocument() bool {
	return true
}

func (c Location) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func (c Location) Hydrate(msi map[string]interface{}, user User) (*Location, error) {
	r := Location{}
	if a, ok := msi["attributes"].(map[string]interface{}); ok {
		r.Attributes.MSIHydrate(a)
	}
	if v, ok := msi["rooms"].([]map[string]interface{}); ok {
		roomsPtr, err := r.Rooms.Hydrate(v)
		if err != nil {
			return nil, err
		}
		if roomsPtr != nil {
			rooms := *roomsPtr
			r.Rooms = rooms
		}
	}
	a, err := r.Address.Hydrate(msi)
	if err != nil {
		return nil, err
	}
	if a != nil {
		r.Address = *a
		if r.Address.Attributes.Id == "" {
			addressPtr := NewAttributes(&user)
			if addressPtr != nil {
				r.Address.Attributes = *addressPtr
			}
		}
	}
	if r.Attributes.Id == "" {
		addressPtr := NewAttributes(&user)
		if addressPtr != nil {
			r.Attributes = *addressPtr
		} 
	}
	if v, ok := msi["name"].(string); ok {
		r.Attributes.Name = v
	}

	return &r, nil
}

func (c Location) HydrateFromRequest(e echo.Context, user User) (*Location, error) {
	bodyPtr, err := GetRequestData(e)
	if err != nil {
		return nil, err
	}
	if bodyPtr == nil {
		err = fmt.Errorf("request body nil")
		return nil, err
	}
	body := *bodyPtr
	locationPtr, err := c.Hydrate(body, user)
	if err != nil {
		return nil, err
	}
	if locationPtr == nil {
		err = fmt.Errorf("location is nil")
		return nil, err
	}
	return locationPtr, nil
}

func (c Location) Load(e echo.Context, user User) (*Location, error) {
	contentId, err := GetContentIdFromUrl(e)
	if err != nil {
		return nil, err
	}
	contentPtr, err := GetContent(contentId)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		return nil, err
	}
	outPtr, err := c.Hydrate(*contentPtr, user)
	if err != nil {
		return nil, err
	}
	return outPtr, nil
}

func (c Location) Merge(oldInput, newInput interface{}, user User) (*Location, error) {
	var old, new Location
	if o, ok := oldInput.(map[string]interface{}); ok {
		ptr, err := c.Hydrate(o, user)
		if err != nil {
			return nil, err
		}
		old = *ptr
	}
	if o, ok := newInput.(map[string]interface{}); ok {
		ptr, err := c.Hydrate(o, user)
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

	attributesPtr, err := c.Attributes.Merge(old.Attributes, new.Attributes)
	if err != nil {
		return nil, err
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes pointer is nil")
		return nil, err
	}
	c.Attributes = *attributesPtr

	addressPtr, err := c.Address.Merge(old.Address, new.Address)
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

func (c Location) Save() error {
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	return redis.CreateJSONDocument(c, "content", ".", false)
}

func (c Location) Update() error {
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	return redis.UpdateJSONDocument(c, "content", ".")
}

func GetRequestData(c echo.Context) (*map[string]interface{}, error) {
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		return nil, err
	}
	return &body, nil
}

type Locations []Location

func (c Locations) IsDocument() bool {
	return true
}

func (c Locations) FindAll() (*Locations, error) {
	content, err := Content{}.FindAll("location")
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

func (c Locations) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func (c Locations) Hydrate(msi []map[string]interface{}, user User) (*Locations, error) {
	locations := Locations{}
	for _, r := range msi {
		location := Location{}
		locationPtr, err := location.Hydrate(r, user)
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

func (c Locations) MergeLocations(msi map[string]interface{}, user User) (string, error) {
	l := Location{}
	h, err := l.Hydrate(msi, user)
	if err != nil {
		return "", err
	}
	if h == nil {
		return "", fmt.Errorf("hydrated location is nil")
	}
	loc := *h
	redis, err := db.NewRedisClient()
	if err != nil {
		logger.Printf("%#v", err)
		return "", err
	}
	redisResponseString, err := redis.ReadJSONDocument("content", ".")
	if err != nil {
		logger.Printf("%#v", err)
		return "", err
	}
	locations := Locations{}
	if redisResponseString != nil {
		responseString := *redisResponseString
		if JSONValidate([]byte(responseString), c) {
			if responseString[0] != '[' {
				responseString = fmt.Sprintf("[%s]", responseString)
			}
			err := json.Unmarshal([]byte(responseString), &c)
			if err != nil {
				logger.Printf("%#v", err)
				return "", err
			}

			for _, l := range c {
				if l.Attributes.Id != loc.Attributes.Id {
					locations = append(locations, l)
				} else {
					locations = append(locations, loc)
				}
			}
		} else {
			locations = c
			locations = append(locations, loc)
		}
		err = redis.CreateJSONDocument(locations, "content", ".", true)
		if err != nil {
			logger.Printf("%#v", err)
			return "", err
		}
	} else {
		logger.Printf("%#v", "db response is nil")
		return "", fmt.Errorf("db response is nil")
	}
	return loc.Attributes.Id, nil
}

func (c Locations) Save() error {
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	return redis.CreateJSONDocument(c, "content", ".", true)
}

func (c Locations) In(id string) bool {
	for _, l := range c {
		if l.Attributes.Id == id {
			return true
		}
	}
	return false
}

func GetLocations() (Locations, error) {
	redis, err := db.NewRedisClient()
	if err != nil {
		return nil, err
	}
	redisResponseString, err := redis.ReadJSONDocument("content", ".")
	if err != nil {
		return nil, err
	}
	if redisResponseString == nil {
		return nil, fmt.Errorf("response is nil")
	}
	responseString := *redisResponseString
	if len(responseString) > 0 && responseString[0] != '[' {
		responseString = fmt.Sprintf("[%s]", responseString)
	}
	locations := Locations{}
	err = json.Unmarshal([]byte(responseString), &locations)
	if err != nil {
		return nil, err
	}
	return locations, nil
}