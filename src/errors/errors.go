package errors

import (
	"context"
	"fmt"
	"log"
	"os"
	"inventory/src/util"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags | log.Lshortfile)
var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type Error struct {
	Message string `json:"message"`
	Input interface{} `json:"input"`
	Trace []string `json:"trace"`
	RequestUri string `json:"requestUri"`
	Package string `json:"package"`
	Function string `json:"function"`
	Struct string `json:"struct"`
	Error error
}

func (c Error) Err(ctx context.Context, e error) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:errors.go:Err")
    }
	if c.Error != nil {
		c.Error = e
		c.Message = c.Error.Error()
		if v, ok := ctx.Value(ckey).([]string); ok {
			c.Trace = v
		}
		logger.Printf("\n%#v\n", c)
		return c.Error
	}
	return nil
}

func (c Error) ErrOrNil(ctx context.Context, ptr interface{}, e error) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:error.go:Error:ErrOrNil")
    }
	if ptr == nil {
		c.Error = fmt.Errorf("pointer is nil")
		c.Message = c.Error.Error()
		if v, ok := ctx.Value(ckey).([]string); ok {
			c.Trace = v
		}
		logger.Printf("\n%#v\n", c)
		return c.Error
	}
	if e != nil {
		return c.Err(ctx, e)
	}
	return nil
}

func ErrOrNil(ctx context.Context, ptr interface{}, e error) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:error.go:ErrOrNil")
    }
	err := Error{}
	return err.ErrOrNil(ctx, ptr, e)	
}
