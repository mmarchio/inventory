package controller

import (
	"encoding/json"
	"fmt"
	"inventory/src/acl"
	"inventory/src/db"
	"inventory/src/login"
	"inventory/src/types"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const ERRORTPL = "error.tpl.html"

type IDocument interface {
	IsDocument() bool
	ToMSI() (map[string]interface{}, error)
	Hydrate(map[string]interface{}) error
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

func getUser(claims jwt.MapClaims) (*types.User, error) {
	redis, err := db.NewRedisClient()
	if err != nil {
		return nil, err
	}
	redisResponseString, err := redis.ReadJSONDocument("user", ".")
	if err != nil {
		return nil, err
	}
	if redisResponseString != nil {
		responseString := *redisResponseString
		if responseString[0] != '[' {
			responseString = fmt.Sprintf("[%s]", responseString)
		}
		var users types.Users
		if redisResponseString != nil {
			err = json.Unmarshal([]byte(responseString), &users)
			if err != nil {
				return nil, err
			}
			for _, u := range users {
				b, err := json.Marshal(claims)
				if err != nil {
					return nil, err
				}
				msi := make(map[string]interface{})
				err = json.Unmarshal(b, &msi)
				if err != nil {
					return nil, err
				}
				if v, ok := msi["username"].(string); ok {
					if u.Username == v {
						return &u, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("bad redis response")
}

func GetRequestData(c echo.Context) (*map[string]interface{}, error) {
	body := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&body)
	if err != nil {
		return nil, err
	}
	return &body, nil
}

func authenticateToken(c echo.Context) (map[string]interface{}, error){
	data := make(map[string]interface{})
	bearer := c.Request().Header.Get("AUTHORIZATION")
	if bearer == "" {
		data["Authenticated"] = false
		return data, fmt.Errorf("bearer not found")
	}
	bearerParts := strings.Split(bearer, " ")
	var token string
	if len(bearerParts) > 1 {
		token = bearerParts[1]
	}
	data["Token"] = token
	_, err := decodeJWT(token, []byte("secret"))
	if err != nil {
		fmt.Printf("test err: %s\n", err.Error())
		data["error"] = err.Error()
		return data, err
	}
	tokenPtr, err := login.ExtendToken(token, []byte("secret"))
	if err != nil {
		return data, err
	}
	if tokenPtr != nil {
		data["Token"] = token
	}
	data["Authenticated"] = true
	return data, nil
}

func CreatePolicy(resource, role, permission string) (*acl.Policy, error) {
	segments := strings.Split(resource, "/")
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	last := segments[len(segments)-1]
	var name string
	if r.Match([]byte(last)) {
		resource = strings.Join(segments[0:len(segments)-2], "/")
		name = fmt.Sprintf("%s-%s", role, strings.Join(segments[0:len(segments)-2], "-"))
	} else {
		name = fmt.Sprintf("%s-%s", role, strings.Join(segments[0:len(segments)-1], "-"))
	}
	polPtr := acl.NewPolicy(name, role, resource, permission)
	if polPtr != nil {
		return polPtr, nil
	}
	return nil, fmt.Errorf("unable to create policy")
}

func UpdateRole(id string, resources acl.Resources) error {
	rolePtr, err := acl.GetRole(id)
	if err != nil {
		return err
	}
	var role acl.Role
	if rolePtr != nil {
		role = *rolePtr
	}
	for _, resource := range resources {
		polPtr, err := CreatePolicy(resource.URL, role.Name, role.DefaultPermisison)
		if err != nil || polPtr == nil {
			return err
		}
		role.Policies = append(role.Policies, *polPtr)
	}
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}

	return redis.CreateJSONDocument(role, "role", ".", true)
}

func UpdatePolicy(role string, resources acl.Resources) error {
	dbPoliciesPtr, err := acl.GetPolicyByRole(role)
	if err != nil {
		return err
	}
	if dbPoliciesPtr != nil {
		dbPolicies := *dbPoliciesPtr
		OUTER:
		for _, outer := range resources {
			for _, inner := range dbPolicies {
				if outer.URL == inner.Resource {
					continue OUTER
				}
			}
			segments := strings.Split(outer.URL, "/")
			segments = append([]string{role}, segments...)
			rolePtr, err := acl.GetRole(role)
			if err != nil {
				return err
			}
			if rolePtr != nil {
				polPtr := acl.NewPolicy(strings.Join(segments, "-"), role, outer.URL, rolePtr.DefaultPermisison)
				if polPtr != nil {
					pol := *polPtr
					dbPolicies = append(dbPolicies, pol)
				}
			}
		}
		redis, err := db.NewRedisClient()
		if err != nil {
			return err
		}
		err = redis.CreateJSONDocument(dbPolicies, "policy", ".", true)
		if err != nil {
			return err
		}
	}
	return nil	
}

func UpdateResources(resources acl.Resources) error {
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	redisResponseString, err := redis.ReadJSONDocument("resource", ".")
	if err != nil {
		return err
	}
	if redisResponseString != nil {
		responseString := *redisResponseString
		if responseString != "" {
			if responseString[0] != '[' {
				responseString = fmt.Sprintf("[%s]", responseString)
			}
			dbResources := acl.Resources{}
			err = json.Unmarshal([]byte(responseString), &dbResources)
			if err != nil {
				return err
			}
			oldLen := len(dbResources)
			for _, outer := range resources {
				for _, inner := range dbResources {
					if outer.URL == inner.URL {
						continue
					}
				}
				dbResources = append(dbResources, outer)				
			}
			newLen := len(dbResources)
			if oldLen != newLen {
				err = redis.CreateJSONDocument(dbResources, "resource", ".", true)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}