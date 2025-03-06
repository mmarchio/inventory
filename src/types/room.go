package types

import (
	"context"
	"inventory/src/errors"
	"inventory/src/util"
)

type Room struct {
	Attributes Attributes `json:"attributes"`
	Zones      Zones      `json:"zone"`
}

func NewRoom(ctx context.Context, createdBy User) *Room {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:room.go:NewRoom")
    }
	r := Room{}
	a := NewAttributes(ctx, &createdBy)
	if a != nil {
		r.Attributes = *a
	}
	return &r
}

func (c Room) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:room.go:room:IsDocument")
    }
	return true
}

func (c Room) ToMSI(ctx context.Context) (map[string]interface{}, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:room.go:room:ToMSI")
    }
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return data, nil
}

func (c Room) Hydrate(ctx context.Context, msi map[string]interface{}) (*Room, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:room.go:room:Hydrate")
    }
	e := errors.Error{}
	room := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := room.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
	}

	if v, ok := msi["zones"].([]map[string]interface{}); ok {
		zones := &Zones{}
		zones, err := zones.Hydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
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
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:room.go:rooms:In")
    }
	for _, r := range c {
		if r.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Rooms) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Rooms, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:room.go:room:Hydrate")
    }
	rooms := c
	for _, r := range msi {
		roomPtr := &Room{}
		roomPtr, err := roomPtr.Hydrate(ctx, r)
		if err != nil {
			e := errors.Error{}
			e.Err(ctx, err)
			return nil, err
		}
		if roomPtr != nil {
			room := *roomPtr
			rooms = append(rooms, room)
		}
	}
	return &rooms, nil
}