package types

import (
	"context"
	"inventory/src/errors"
	"inventory/src/util"
)

type Container struct {
	Attributes Attributes `json:"attributes"`
	Items      Items      `json:"items"`
}

func NewContainer(ctx context.Context, createdBy *User) (*Container, *map[string]errors.Error)
 {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:container.go:NewContainer")
    }
	container := Container{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		container.Attributes = *attributesPtr
	}
	return &container, nil
}

func (c Container) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:container.go:Container:IsDocument")
    }
	return true
}

func (c Container) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error)
 {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:container.go:Container:ToMSI")
    }
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
        e.Err(ctx, err)
		return nil, err
	}
	return data, nil
}

func (c Container) Hydrate(ctx context.Context, msi map[string]interface{}) (*Container, *map[string]errors.Error)
 {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:container.go:Container:Hydrate")
    }
	e := errors.Error{}
	container := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := container.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
	}

	if v, ok := msi["items"].([]map[string]interface{}); ok {
		itemsPtr, err := container.Items.Hydrate(ctx, v)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if itemsPtr != nil {
			container.Items = *itemsPtr
		}
	}
	return &container, nil
}

type Containers []Container

func (c Containers) In(ctx context.Context, id string) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:container.go:Containers:In")
    }
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Containers) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Containers, *map[string]errors.Error)
 {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:container.go:Container:Hydrate")
    }
	e := errors.Error{}
	containers := c
	for _, r := range msi {
		container := Container{}
		containerPtr, err := container.Hydrate(ctx, r)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		if containerPtr != nil {
			containers = append(containers, *containerPtr)
		}
	}
	return &containers, nil
}