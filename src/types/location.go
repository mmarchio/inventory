package types

import (
	"encoding/json"
	"fmt"
	"inventory/src/db"
)

type Location struct {
	Attributes Attributes `json:"attributes"`
	Rooms      Rooms      `json:"rooms"`
	Address    Address    `json:"address"`
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
			logger.Printf("%#v", err)
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

type Locations []Location

func (c Locations) IsDocument() bool {
	return true
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
			c = append(c, loc)
		} else {
			c = append(c, loc)
		}
		err = redis.CreateJSONDocument(c, "content", ".", true)
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