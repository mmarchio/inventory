package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"regexp"

	"inventory/src/acl"
	"inventory/src/controller"
	"inventory/src/errors"
	system_init "inventory/src/init"
	"inventory/src/util"

	"github.com/joho/godotenv"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type IDocument interface {
	IsDocument() bool
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	err := t.templates.ExecuteTemplate(w, name, data)
	if err != nil {
		msg := make(map[string]interface{})
		msg["error"] = err.Error()
		msg["input"] = data
		fmt.Printf("\n\n*****rendering error****\n\n%#v", msg)
	}
	return err
}

func JWTSkipper(c echo.Context) bool {
	pattern := "/api/.+"
	r := regexp.MustCompile(pattern)
	if c.Request().URL.Path == "/api/login" || !r.Match([]byte(c.Request().URL.Path)) {
		return true
	}
	return false
}

func UpdateCtx(ctx context.Context, key, value string) context.Context {
	var stack []any
	if v, ok := ctx.Value(key).([]any); ok {
		stack = v
	}
	stack = append(stack, value)
	return context.WithValue(ctx, key, value)
}

func main() {
	ctx := context.Background()

	updateCtx := func(ctx context.Context, key util.CtxKey, value string) context.Context {
		var stack []any
		if v, ok := ctx.Value(key).([]any); ok {
			stack = v
		}
		stack = append(stack, value)
		return context.WithValue(ctx, key, stack)
	}
	ctx = context.WithValue(ctx, ukey, updateCtx)

	ierr := errors.Error{
		Package: "main",
	}

	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
	e := echo.New()
	wd, err := os.Getwd()
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}
	e.Static("/", wd+"/static")
	e.Use(echojwt.WithConfig(echojwt.Config{
		// ...
		SigningKey: []byte("secret"),
		Skipper: JWTSkipper,
		// ...
		}))
	e.Use(acl.ACL)

	t := &Template{
		templates: template.Must(template.ParseGlob("view/tpl/*.tpl.html")),
	}

	err = system_init.CreateSystemUser(ctx)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	err = acl.CreateSystemPolicies(ctx)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	err = system_init.CreateAdminRole(ctx)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags | log.Lshortfile)

	indexController := controller.IndexController{
		Logger: logger,
		Error: errors.Error{
			Package: "controller",
			Struct: "IndexController",
		},
		Ctx: ctx,
	}
	err = indexController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	dashboardController := controller.DashboardController{
		Logger: logger,
		Error: errors.Error{
			Package: "controller",
			Struct: "DashboardController",
		},
		Ctx: ctx,
	}
	err = dashboardController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	settingsController := controller.SettingsController{
		Logger: logger,
		Error: errors.Error{
			Package: "controller",
			Struct: "SettingsController",
		},
		Ctx: ctx,
	}
	err = settingsController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	locationController := controller.LocationController{
		Error: errors.Error{
			Package: "controller",
			Struct: "LocationController",
		},
		Ctx: ctx,
	}
	err = locationController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	roomController := controller.RoomController{
		Error: errors.Error{
			Package: "controller",
			Struct: "RoomController",
		},
		Ctx: ctx,
	}
	err = roomController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	zoneController := controller.ZoneController{
		Error: errors.Error{
			Package: "controller",
			Struct: "ZoneController",
		},
		Ctx: ctx,
	}
	err = zoneController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	containerController := controller.ContainerController{
		Error: errors.Error{
			Package: "controller",
			Struct: "ContainerController",
		},
		Ctx: ctx,
	}
	err = containerController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	itemController := controller.ItemController{
		Error: errors.Error{
			Package: "controller",
			Struct: "ItemController",
		},
		Ctx: ctx,
	}
	err = itemController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	loginController := controller.LoginController{
		Error: errors.Error{
			Package: "controller",
			Struct: "LoginController",
		},
		Ctx: ctx,
	}
	err = loginController.RegisterResources(e)
	if err != nil {
		ierr.Error = err
		ierr.Err(ctx, err)
		panic(err)
	}

	e.Renderer = t

	e.Logger.Fatal(e.Start(":8080"))
}

