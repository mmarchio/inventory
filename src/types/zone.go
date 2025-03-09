package types

import (
	"context"
	"inventory/src/errors"
	"inventory/src/util"
)

type Zone struct {
	Attributes Attributes `json:"attributes"`
	Containers Containers `json:"containers"`
}

func NewZone(ctx context.Context, createdBy *User) (*Zone, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:zone.go:NewZone")
    }
	zone := Zone{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		zone.Attributes = *attributesPtr
	}
	return &zone, nil
}

func (c Zone) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:zone.go:Zone:IsDocument")
    }
	return true
}

func (c Zone) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:zone.go:Zone:ToMSI")
    }
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return data, nil
}

func (c Zone) Hydrate(ctx context.Context, msi map[string]interface{}) (*Zone, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:zone.go:Zone:Hydrate")
    }
	e := errors.Error{}
	zone := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := zone.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
	}
	if v, ok := msi["containers"].([]map[string]interface{}); ok {
		containersPtr, err := c.Containers.Hydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if containersPtr != nil {
			zone.Containers = *containersPtr
		}
	}
	return &zone, nil
}

type Zones []Zone

func (c Zones) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Zones, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:zone.go:Zones:Hydrate")
    }
	zones := Zones{}
	for _, r := range msi {
		zonePtr := &Zone{}
		zonePtr, err := zonePtr.Hydrate(ctx, r)
		if err != nil {
			e := errors.Error{}
			e.Err(ctx, err)
			return nil, err
		}
		if zonePtr != nil {
			zone := *zonePtr
			zones = append(zones, zone)
		}
	}
	return &zones, nil
}

func (c Zones) In(ctx context.Context, id string) bool {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:zone.go:Zones:In")
    }
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}