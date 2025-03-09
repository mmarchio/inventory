package types

import (
	"context"
	"inventory/src/errors"
	"inventory/src/util"
)

type Item struct {
	Attributes Attributes `json:"attributes"`
	Quantity   float64    `json:"quantity"`
	UOMS       string     `json:"oums"`
}

func NewItem(ctx context.Context, createdBy *User) (*Item, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:item.go:NewItem")
    }
	item := Item{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		item.Attributes = *attributesPtr
	}
	return &item, nil
}

func (c Item) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:item.go:Item:IsDocument")
    }
	return true
}

func (c Item) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:item.go:Item:ToMSI")
    }
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
	}
	return data, nil
}

func (c Item) Hydrate(ctx context.Context, msi map[string]interface{}) (*Item, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:item.go:Item:Hydrate")
    }
	e := errors.Error{}
	r := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := r.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
	}
	if v, ok := msi["quantity"].(float64); ok {
		r.Quantity = v
	}

	if v, ok := msi["uoms"].(string); ok {
		r.UOMS = v
	}

	return &r, nil
}

type Items []Item

func (c Items) In(ctx context.Context, id string) bool {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:item.go:Items:In")
    }
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Items) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Items, *map[string]errors.Error)
 {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:item.go:Items:Hydrate")
    }
	e := errors.Error{}
	items := c
	for _, r := range msi {
		item := Item{}
		itemPtr, err := item.Hydrate(ctx, r)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if itemPtr != nil {
			items = append(items, *itemPtr)
		}
	}
	return &items, nil
}