package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"

	"github.com/google/uuid"
)

type Resource struct {
	types.Attributes
	Id  string `json:"id"`
	URL string `json:"url"`
}

func (c Resource) New(ctx context.Context) (*Resource,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resource:New")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "New", "Resource")
	attributesPtr, erp := c.Attributes.New(nil)
	if erp != nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if attributesPtr == nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, fmt.Errorf("attributes pointer is nil"), &e)
		return nil, &e
	}
	c.Attributes = *attributesPtr
	resource := c
	resource.Id = uuid.NewString()
	return &resource, nil
}

func (c Resource) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:ToContent")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "ToContent", "Resource")
	content := types.Content{}
	content.Attributes.Id = c.Id
	content.Attributes.ContentType = "resource"
	jbytes, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content.Content = jbytes
	return &content, nil
}

func (c Resource) PGRead(ctx context.Context) (*Resource,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGRead")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "PGRead", "Resource")
	contentPtr, erp := types.Content{}.Read(ctx, c.Id)
	if erp != nil {
		fidx := "types:Content:Read"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		e[idx].Err(ctx, err)
		return nil, &e
	}
	content := *contentPtr
	resource := c
	err := json.Unmarshal(content.Content, &resource)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	return &resource, nil
}

func (c Resource) PGCreate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGCreate")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "PGCreate", "Resource")
	erp := types.Content{}.Create(ctx, c)
	if erp != nil {
		fidx := "types:Content:Create"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Resource) PGUpdate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGUpdate")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "PGUpdate", "Resource")
	contentPtr, erp := c.ToContent(ctx)
	if erp != nil {
		fidx := "acl:Resource:ToContent"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		e[idx].Err(ctx, err)
		return &e
	}
	content := *contentPtr
	erp = content.Update(ctx, c)
	if erp != nil {
		fidx := "types:Content:Update"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Resource) PGDelete(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGDelete")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "PGDelete", "Resource")
	erp := types.Content{}.Delete(ctx, c.Attributes.Id)
	if erp != nil {
		fidx := "types:Content:Delete"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c Resource) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resource:IsDocument")
	}
	return true
}

func (c Resource) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "New", "Resource")
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	return r, nil
}

type Resources []Resource

func (c Resources) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resources:In")
	}
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Resources) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resources:IsDocument")
	}
	return true
}

func (c Resources) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resources:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "ToMSI", "Resources")
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return r, &e
	}
	return r, nil
}

func FindResources(ctx context.Context) (*Resources,*map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:FindResources")
	}
	e, idx := errors.Error{}.New(ctx, "resource.go", "acl", "FindResources", "Resources")
	content, erp := types.Content{}.FindAll(ctx, "resource")
	if erp != nil {
		fidx := "types:Content:FindAll"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	r := Resources{}
	for _, c := range content {
		resource := Resource{}
		err := json.Unmarshal(c.Content, &resource)
		if err != nil {
			fidx := "json:Unmarshal"
			errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
			return nil, &e
		}
		r = append(r, resource)
	}
	return &r, nil
}
