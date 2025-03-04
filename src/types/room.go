package types

import "context"

type Room struct {
	Attributes Attributes `json:"attributes"`
	Zones      Zones      `json:"zone"`
}

func NewRoom(ctx context.Context, createdBy User) *Room {
	r := Room{}
	a := NewAttributes(ctx, &createdBy)
	if a != nil {
		r.Attributes = *a
	}
	return &r
}

func (c Room) IsDocument(ctx context.Context) bool {
	return true
}

func (c Room) ToMSI(ctx context.Context) (map[string]interface{}, error) {
	return toMSI(ctx, c)
}

func (c Room) Hydrate(ctx context.Context, msi map[string]interface{}) (*Room, error) {
	room := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := room.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			return nil, err
		}
	}

	if v, ok := msi["zones"].([]map[string]interface{}); ok {
		zones := &Zones{}
		zones, err := zones.Hydrate(ctx, v)
		if err != nil {
			return nil, err
		}
		if zones != nil {
			room.Zones = *zones
		}
	}
	return &room, nil
}

type Rooms []Room

func (c Rooms) In(ctx context.Context, id string) bool {
	for _, r := range c {
		if r.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Rooms) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Rooms, error) {
	rooms := c
	for _, r := range msi {
		roomPtr := &Room{}
		roomPtr, err := roomPtr.Hydrate(ctx, r)
		if err != nil {
			return nil, err
		}
		if roomPtr != nil {
			room := *roomPtr
			rooms = append(rooms, room)
		}
	}
	return &rooms, nil
}