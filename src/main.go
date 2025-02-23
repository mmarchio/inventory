package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"inventory/src/acl"
	"inventory/src/controller"
	"inventory/src/db"
	system_init "inventory/src/init"
	"inventory/src/login"
	"inventory/src/types"

	"github.com/golang-jwt/jwt/v5"
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
		}
		err = indexController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		dashboardController := controller.DashboardController{
			Logger: logger,
		}
		err = dashboardController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		settingsController := controller.SettingsController{
			Logger: logger,
		}
		err = settingsController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		locationController := controller.LocationController{}
		err = locationController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		roomController := controller.RoomController{}
		err = roomController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		zoneController := controller.ZoneController{}
		err = zoneController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		containerController := controller.ContainerController{}
		err = containerController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		itemController := controller.ItemController{}
		err = itemController.RegisterResources(e)
		if err != nil {
			panic(err)
		}

		e.Renderer = t

		e.POST("/api/login", APILoginHandler)
		e.GET("/logout", LogoutHandler)

		e.Logger.Fatal(e.Start(":8080"))
}

func APILoginHandler(c echo.Context) error {
	msg := make(map[string]interface{})
	redis, err := db.NewRedisClient()
	if err != nil {
		msg["error"] = fmt.Sprintf("redis: %s", err.Error())
		return c.JSON(http.StatusInternalServerError, msg)
	}
	requestBody, err := getRequestData(c) 
	if err != nil {
		msg["error"] = fmt.Sprintf("json: %s", err.Error())
	}
	if requestBody == nil {
		msg["error"] = "request body empty"
		return c.JSON(http.StatusBadRequest, msg)
	}
	body := *requestBody
	creds := login.Credentials{}
	if v, ok := body["username"].(string); ok {
		creds.Username = v
	}
	if v, ok := body["password"].(string); ok {
		creds.Password = v
	}
	res, err := redis.ReadJSONDocument("auth", ".")
	if err != nil {
		msg["error"] = fmt.Sprintf("redis: %s", err.Error())
		return c.JSON(http.StatusInternalServerError, msg)
	}
	var jsonRes string
	if res != nil {
		jsonRes = *res
	}
	if jsonRes[0] != '[' {
		jsonRes = fmt.Sprintf("[%s]", jsonRes)
	}
	users := types.Users{}
	err = json.Unmarshal([]byte(jsonRes), &users)
	if err != nil {
		msg["error"] = fmt.Sprintf("json: %s", err.Error())
		msg["input"] = jsonRes
		return c.JSON(http.StatusInternalServerError, msg)
	}

	for _, u := range users {
		if u.Username == creds.Username {
			auth, err := login.Login(u.Username, creds.Password, u.Password)
			if err != nil {
				msg["error"] = fmt.Sprintf("auth: %s", err.Error())
				return c.JSON(http.StatusInternalServerError, msg)
			}
			if auth != nil {
				c.SetCookie(auth)
				c.Set("Authenticated", true)
				c.Set("user", u)
				c.Response().Header().Set("AUTHORIZATION", fmt.Sprintf("Bearer %s", auth.Value))
				msg["authenticated"] = true
				msg["token"] = auth.Value;
				return c.JSON(http.StatusOK, msg)
			}
		}
	}

	msg["error"] = "user not found"
	return c.JSON(http.StatusNotFound, msg)
}

func getRequestData(c echo.Context) (*map[string]interface{}, error) {
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		return nil, err
	}
	return &body, nil
}

func JWTSkipper(c echo.Context) bool {
	pattern := "/api/.+"
	r := regexp.MustCompile(pattern)
	if c.Request().URL.Path == "/api/login" || !r.Match([]byte(c.Request().URL.Path)) {
		return true
	}
	return false
}

func decodeJWT(tokenString string, secretKey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
    
	return nil, fmt.Errorf("invalid token")
}

func LogoutHandler(c echo.Context) error {
	data := make(map[string]interface{})
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		data["Authenticated"] = false
		return c.Render(http.StatusOK, "index.tpl.html", data)
	}
	token := strings.Split(bearer, " ")[1]
	_, err := decodeJWT(token, []byte("secret"))
	if err != nil {
		return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
	}
	return c.Render(http.StatusOK, "index.tpl.html", nil)
}