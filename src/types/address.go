package types

import (
	"context"
	"fmt"
)

type Address struct {
	Attributes
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
	City     string `json:"city"`
	State    string `json:"state"`
	Zipcode  string `json:"zipcode"`
	Country  string `json:"country"`
}

func NewAddress(ctx context.Context, createdBy *User) (*Address, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:address.go:NewAddress")
    }
	address := Address{}
	attributesPtr := NewAttributes(ctx, createdBy)
	if attributesPtr != nil {
		address.Attributes = *attributesPtr
	}
	return &address, nil
}

func (c Address) Merge(ctx context.Context, oldInput, newInput interface{}) (*Address, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:address.go:Address:Merge")
    }
	var old, new Address
	if o, ok := oldInput.(map[string]interface{}); ok {
		oldPtr, err := c.Hydrate(ctx, o)
		if err != nil {
			return nil, err
		}
		if oldPtr == nil {
			err = fmt.Errorf("old pointer is nil")
			return nil, err
		}
		old = *oldPtr
	}
	if o, ok := newInput.(map[string]interface{}); ok {
		newPtr, err := c.Hydrate(ctx, o)
		if err != nil {
			return nil, err
		}
		if newPtr == nil {
			err = fmt.Errorf("new pointer is nil")
			return nil, err
		}
		new = *newPtr
	}
	if o, ok := oldInput.(Address); ok {
		old = o
	}
	if o, ok := newInput.(Address); ok {
		new = o
	}
	
	attributesPtr, err := old.Attributes.Merge(ctx, old.Attributes, new.Attributes)
	if err != nil {
		return nil, err
	}
	if attributesPtr != nil {
		new.Attributes = *attributesPtr
	}
	if new.Address1 == "" {
		new.Address1 = old.Address1
	}
	if new.Address2 == "" {
		new.Address2 = old.Address2
	}
	if new.City == "" {
		new.City = old.City
	}
	if new.State == "" {
		new.State = old.State
	}
	if new.Country == "" {
		new.Country = old.Country
	}
	return &new, nil
}

func (c Address) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:address.go:Address:IsDocument")
    }
	return true
}

func (c Address) ToMSI(ctx context.Context) (map[string]interface{}, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:address.go:Address:ToMSI")
    }
	return toMSI(ctx, c)
}

func (c Address) Hydrate(ctx context.Context, msi map[string]interface{}) (*Address, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:address.go:Address:Hydrate")
    }
	address := c
	if v, ok := msi["attributes"].(map[string]interface{}); ok {
		err := c.Attributes.MSIHydrate(ctx, v)
		if err != nil {
			return nil, err
		}
	}
	if a, ok := msi["address"].(map[string]interface{}); ok {
		if v, ok := a["address1"].(string); ok {
			address.Address1 = v
		}

		if v, ok := a["address2"].(string); ok {
			address.Address2 = v
		}

		if v, ok := a["city"].(string); ok {
			address.City = v
		}

		if v, ok := a["state"].(string); ok {
			address.State = v
		}

		if v, ok := a["zipcode"].(string); ok {
			address.Zipcode = v
		}

		if v, ok := a["country"].(string); ok {
			address.Country = v
		}
	}
	if v, ok := msi["address1"].(string); ok {
		address.Address1 = v
	}

	if v, ok := msi["address2"].(string); ok {
		address.Address2 = v
	}

	if v, ok := msi["city"].(string); ok {
		address.City = v
	}

	if v, ok := msi["state"].(string); ok {
		address.State = v
	}

	if v, ok := msi["zipcode"].(string); ok {
		address.Zipcode = v
	}

	if v, ok := msi["country"].(string); ok {
		address.Country = v
	}
	return &address, nil
}