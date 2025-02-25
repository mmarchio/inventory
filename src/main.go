package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"regexp"

	"inventory/src/acl"
	"inventory/src/controller"
	"inventory/src/db"
	"inventory/src/errors"
	system_init "inventory/src/init"

	"github.com/joho/godotenv"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

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

func main() {
		err := godotenv.Load()
		if err != nil {
			panic(err)
		}
		e := echo.New()
		wd, err := os.Getwd()
		if err != nil {
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

		redis, err := db.NewRedisClient()
		if err != nil {
			panic(err)
		}
		redisResponseString, err := redis.ReadJSONDocument("auth", ".")
		if err != nil {
			panic(err)
		}
		if redisResponseString != nil {
			responseString := *redisResponseString
			if responseString == "" || responseString == "{}" {
				err = system_init.CreateSystemUser()
				if err != nil {
					panic(err)
				}
			}
		}
		redisResponseString, err = redis.ReadJSONDocument("policy", ".")
		if err != nil {
			panic(err)
		}
		if redisResponseString != nil {
			responseString := *redisResponseString
			if responseString == "" || responseString == "{}" {
				err = acl.CreateSystemPolicies()
				if err != nil {
					panic(err)
				}
			}
		}

		redisResponseString, err = redis.ReadJSONDocument("role", ".")
		if err != nil {
			panic(err)
		}
		if redisResponseString != nil {
			responseString := *redisResponseString
			if responseString == "" || responseString == "[]" {
				err = system_init.CreateAdminRole()
				if err != nil {
					panic(err)
				}
			}
		}

		logger := log.New(os.Stdout, "", log.LstdFlags | log.Lshortfile)

		indexController := controller.IndexController{
			Logger: logger,
			Error: errors.Error{
				Package: "controller",
				Struct: "IndexController",
			},
		}
		err = indexController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		dashboardController := controller.DashboardController{
			Logger: logger,
			Error: errors.Error{
				Package: "controller",
				Struct: "DashboardController",
			},
		}
		err = dashboardController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		settingsController := controller.SettingsController{
			Logger: logger,
			Error: errors.Error{
				Package: "controller",
				Struct: "SettingsController",
			},
		}
		err = settingsController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		locationController := controller.LocationController{
			Error: errors.Error{
				Package: "controller",
				Struct: "LocationController",
			},
		}
		err = locationController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		roomController := controller.RoomController{
			Error: errors.Error{
				Package: "controller",
				Struct: "RoomController",
			},
		}
		err = roomController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		zoneController := controller.ZoneController{
			Error: errors.Error{
				Package: "controller",
				Struct: "ZoneController",
			},
		}
		err = zoneController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		containerController := controller.ContainerController{
			Error: errors.Error{
				Package: "controller",
				Struct: "ContainerController",
			},
		}
		err = containerController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		itemController := controller.ItemController{
			Error: errors.Error{
				Package: "controller",
				Struct: "ItemController",
			},
		}
		err = itemController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		loginController := controller.LoginController{
			Error: errors.Error{
				Package: "controller",
				Struct: "LoginController",
			},
		}
		err = loginController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		e.Renderer = t

		e.Logger.Fatal(e.Start(":8080"))
}

