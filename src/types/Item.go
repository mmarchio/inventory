package types

import "context"

type Item struct {
	Attributes Attributes `json:"attributes"`
	Quantity   float64    `json:"quantity"`
	UOMS       string     `json:"oums"`
}

func NewItem(ctx context.Context, createdBy *User) (*Item, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:item.go:NewItem")
    }
	item := Item{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		item.Attributes = *attributesPtr
	}
	return &item, nil
}

func (c Item) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:item.go:Item:IsDocument")
    }
	return true
}

func (c Item) ToMSI(ctx context.Context) (map[string]interface{}, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:item.go:Item:ToMSI")
    }
	return toMSI(ctx, c)
}

func (c Item) Hydrate(ctx context.Context, msi map[string]interface{}) (*Item, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:item.go:Item:Hydrate")
    }
	r := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := r.Attributes.MSIHydrate(ctx, v)
		if err != nil {
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
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:item.go:Items:In")
    }
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Items) Hydrate(ctx context.Context, msi []map[string]interface{}) (*Items, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:item.go:Items:Hydrate")
    }
	items := c
	for _, r := range msi {
		item := Item{}
		itemPtr, err := item.Hydrate(ctx, r)
		if err != nil {
			return nil, err
		}
		if itemPtr != nil {
			items = append(items, *itemPtr)
		}
	}
	return &items, nil
}