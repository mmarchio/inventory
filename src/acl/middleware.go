package acl

import (
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"os"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)


type IDocument interface{
	IsDocument() bool
	ToMSI() (map[string]interface{}, error)
}

func ACL(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		e := errors.Error{
			RequestUri: c.Request().RequestURI,
			Package: "acl",
			Function: "ACL",
		}
		if err := next(c); err != nil {
			c.Error(err)
		}
		if skipper(c) {
			return nil
		}
		token, err := GetBearerToken(c)
		if err != nil {
			return e.Err(err)
		}
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			err := fmt.Errorf("secret not found")
			return e.Err(err)
		}
		// if authorization[len(authorization)-2:len(authorization)-1] != "==" {
		// 	authorization = fmt.Sprintf("%s==", authorization)
		// }

		claims, err := DecodeJWT(token, []byte("secret"))
		if err != nil {
			return e.Err(err)
		}
		user, err := GetUser(claims)
		if err != nil {
			return e.Err(err)
		}
		if user != nil {
			us := *user
			policyPtr, err := getResourcePolicy(us, c.Request().URL.Path)
			if e.Err(err) != nil {
				return err
			}
			if policyPtr == nil {
				err = fmt.Errorf("policy is nil")
				return e.Err(err)
			}
			policy := *policyPtr
			if policy.IsContent {
				auth, err := PermissionsHandler(c, policy)
				if err != nil {
					return e.Err(err)
				}
				if auth {
					return nil
				} else {
					err = fmt.Errorf("access forbidden")
					return e.Err(err)
				}
			}
			return nil
		}
		return e.Err(err)
	}
}

func DecodeJWT(tokenString string, secretKey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {

			err2 := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		return nil, err2
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	err = fmt.Errorf("invalid token")
	return nil, err
}

func GetUser(claims jwt.MapClaims) (*types.User, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	msi := make(map[string]interface{})
	err = json.Unmarshal(b, &msi)
	if err != nil {
		return nil, err
	}
	var jstring string
	if v, ok := msi["username"].(string); ok {
		jstring = fmt.Sprintf("{\"username\": \"%s\"}", v)
	}
	userPtr, err := types.User{}.FindBy(jstring)
	if err != nil {
		return nil, err
	}
	if userPtr == nil {
		return nil, fmt.Errorf("user is nil")
	}
	return userPtr, nil
}

func getResourcePolicy(u types.User, resource string) (*Policy, error) {
	policiesPtr, err := Policies{}.FindPolicies()
	if err != nil {
		return nil, err
	}
	if policiesPtr == nil {
		return nil, fmt.Errorf("policies is nil")
	}
	policies := *policiesPtr
	for _, p := range policies {
		resource = pathToResource(resource)
		if resource == p.Resource && u.HasRole(p.Role) {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("%s", resource)
}

func skipper(c echo.Context) bool {
	pattern := regexp.QuoteMeta(".js")+"|"+regexp.QuoteMeta(".css")+"|"+regexp.QuoteMeta("logout")+"|"+regexp.QuoteMeta("login")
	r := regexp.MustCompile(pattern)
	if c.Request().URL.Path == "" || c.Request().URL.Path == "/" || r.Match([]byte(c.Request().URL.Path)) {
		return true
	}
	return false
}

func GetUsableClaims(c echo.Context) (*map[string]interface{}, error) {
	token, err := GetBearerToken(c)
	if err != nil {
		return nil, err
	}
	jwt, err := DecodeJWT(token, []byte("secret"))
	if err != nil {
		return nil, err
	}
	msi := make(map[string]interface{})
	b, err := json.Marshal(jwt)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &msi)
	if err != nil {
		return nil, err
	}
	return &msi, nil
}

func pathToResource(url string) string {
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	segments := strings.Split(url, "/")
	s := url
	if r.Match([]byte(segments[len(segments)-1])) {
		s = strings.Join(segments[0:len(segments)-1], "/")
	}
	return s
}

func PermissionsHandler(c echo.Context, p Policy) (bool, error) {
	userPtr, err := GetUserFromContext(c)
	if err != nil {
		return false, err
	}
	if userPtr == nil {
		err := fmt.Errorf("user is nil")
		return false, err
	}
	user := *userPtr
	segments := strings.Split(c.Request().RequestURI, "/")
	contentId := segments[len(segments)-1]
	contentPtr, err := types.GetContent(contentId)
	if err != nil {
		return false, err
	}
	if contentPtr == nil {
		err := fmt.Errorf("content pointer is nil")
		return false, err
	}
	content := *contentPtr
	if user.HasRole(p.Role) {
		switch p.Permission.Name {
		case "all":
			return true, nil
		case "created":
			if user.Attributes.Id == content.Attributes.CreatedBy {
				return true, nil
			}
		case "owned":
			if user.Attributes.Id == content.Attributes.Owner {
				return true, nil
			}
		default:
			return false, nil
		}
	}
	return false, err
}