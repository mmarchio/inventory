package controller

import (
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/login"
	"inventory/src/types"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type SettingsController struct {
	Logger *log.Logger
	Error errors.Error
}

func (s SettingsController) Get() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.RequestUri = c.Request().RequestURI
		s.Error.Function = "Get"
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"

		usersPtr, err := types.GetUsers()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if usersPtr != nil {
			data["Users"] = *usersPtr
		}

		rolesPtr, err := acl.GetRoles()
		if err != nil {
			if err.Error() != "roles not found" {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
		}
		if rolesPtr != nil {
			data["Roles"] = *rolesPtr
		}

		policiesPtr, err := acl.GetPolicies()
		if err != nil {
			if err.Error() != "policies not found" {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
		}
		if policiesPtr != nil {
			data["Policies"] = *policiesPtr
		}

		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}

		return c.Render(http.StatusOK, "settings.tpl.html", data)
	}
}

func (s SettingsController) GetUserCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.RequestUri = c.Request().RequestURI
		s.Error.Function = "GetUserCreate"
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"

		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		return c.Render(http.StatusOK, "settings.user.create.tpl.html", data)
	}
}

func (s SettingsController) GetUserEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetUserEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"

		userPtr, err := types.GetUser(c.Param("id"))
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if userPtr != nil {
			user := *userPtr
			data["Entity"] = user
			if user.DOB != nil {
				dob := *user.DOB
				data["DOB"] = dob.Format("01/02/2006")
			} else {
				err = fmt.Errorf("entity dob nil")
				s.Error.Err(err)
			}
		} else {
			err = fmt.Errorf("entity pointer nil")
			s.Error.Err(err)
		}
		rolesPtr, err := acl.GetRoles()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if rolesPtr != nil {
			roles := *rolesPtr
			rolesMSI := make([]map[string]interface{}, 0)
			for _, r := range roles {
				roleMSI := make(map[string]interface{})
				if u, ok := data["Entity"].(types.User); ok {
					for _, ur := range u.Roles {
						if r.Name == ur {
							roleMSI["Selected"] = 1
						}
						roleMSI["Name"] = r.Name
						rolesMSI = append(rolesMSI, roleMSI)
					}
					data["Roles"] = rolesMSI
				}
			}
		}

		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		return c.Render(http.StatusOK, "settings.user.edit.tpl.html", data)
	}
}
 
func (s SettingsController) GetUserDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetUserDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		user := types.User{}
		user.Attributes.Id = c.Param("id")
		err = user.PGDelete()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}

		data["msg"] = "user deleted"
		return c.Render(http.StatusOK, "dashboard.tpl.html", data)
	}
}

func (s SettingsController) GetRoleCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetRoleCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				s.Error.Err(err)
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "settings.role.create.tpl.html", data)
	}
}

func (s SettingsController) GetRoleEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetRoleEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"

		rolePtr, err := acl.GetRole(c.Param("id"))
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}

		if rolePtr != nil {
			role := *rolePtr
			policiesPtr, err := acl.GetPolicyByRole(role.Name)
			if err != nil {
				s.Error.Err(err)
				data["error"] = err.Error()
				return c.Render(http.StatusInternalServerError, ERRORTPL, data)
			}
			if policiesPtr != nil {
				policies := *policiesPtr
				permissions := acl.Permissions{}
				for _, p := range policies {
					permission := acl.Permission{}
					segments := strings.Split(p.Resource, "/")
					if len(segments) == 3 {
						for i, t := range segments {
							segments[i] = fmt.Sprintf("%s%s", strings.ToUpper(string(t[0])), string(t[1:]))
						}
						permission.Name = strings.Join(segments, "")
						permissions = append(permissions, permission)
					}
				}
				data["permissions"] = permissions
			}
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "settings.role.edit.tpl.html", data)
	}
}
 
func (s SettingsController) GetRoleDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetRoleDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			s.Error.Err(err)
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		role := acl.Role{}
		role.Attributes.Id = c.Param("id")
		err = role.PGDelete()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["msg"] = "user deleted"
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "dashboard.tpl.html", data)
	}
}

func (s SettingsController) GetPolicyCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetPolicyCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			s.Error.Err(err)
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "settings.policy.create.tpl.html", data)
	}
}

func (s SettingsController) GetPolicyEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetPolicyEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			s.Error.Err(err)
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "settings.role.create.tpl.html", data)
	}
}

func (s SettingsController) GetPolicyDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "GetPolicyDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			data["PageTitle"] = "Inventory Management"
			if err.Error() == "bearer not found" {
				return c.Render(http.StatusOK, "index.tpl.html", data)
			}
			s.Error.Err(err)
			return c.Render(http.StatusInternalServerError, ERRORTPL, data)
		}
		data["PageTitle"] = "Inventory Management"
		if token, ok := data["Token"].(string); ok {
			claims, err := acl.DecodeJWT(token, []byte("secret"))
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			user, err := acl.GetUser(claims)
			if err != nil {
				s.Error.Err(err)
				return c.Render(http.StatusInternalServerError, "error.tpl.html", err.Error())
			}
			data["User"] = user
		}
		data["PageTitle"] = "Inventory Management"
		return c.Render(http.StatusOK, "settings.role.create.tpl.html", data)
	}
}

func (s SettingsController) PostApiUserCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiUserCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		requestBody, err := GetRequestData(c)
		if err != nil {
			s.Error.Err(err)
			data["error"] = fmt.Sprintf("json: %s", err.Error())
			return c.JSON(http.StatusInternalServerError, data)
		}
		var body map[string]interface{}
		if requestBody != nil {
			body = *requestBody
		} else {
			err = fmt.Errorf("empty post body")
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusBadRequest, data)
		}
	
		if p, ok := body["password"].(string); ok {
			if cp, ok := body["confirm_password"].(string); ok {
				if p != cp {
					data["error"] = "passwords do not match"
					return c.JSON(http.StatusBadRequest, data)
				}
			} 
		}
		user := &types.User{}
		user, err = user.Hydrate(body)
		if err != nil {
			s.Error.Err(err)
			data["error"] = fmt.Sprintf("user hydrate: %s", err.Error())
			return c.JSON(http.StatusInternalServerError, err)
		}
		err = user.PGCreate()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, err)
		}

		hash, err := login.HashPassword(user.Password)
		if err != nil {
			s.Error.Err(err)
			data["error"] = fmt.Sprintf("login: %s", err.Error())
			return c.JSON(http.StatusInternalServerError, data)
		}
		creds := login.Credentials{
			Username: user.Username,
			Password: hash,
		}

		attributes := types.NewAttributes(nil)
		user.Attributes = *attributes
		user.Password = ""
		err = creds.PGCreate()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		return c.JSON(http.StatusOK, user.Id)
	}
}

func (s SettingsController) PostApiRoleCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		return nil
	}
}

func (s SettingsController) PostApiRoleEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		return nil
	}
}

func (s SettingsController) PostApiRoleDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		return nil
	}
}

func (s SettingsController) PostApiUserEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiUserEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}

		userPtr, err := types.GetUser(c.Param("id"))
		if err != nil {
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		if userPtr == nil {
			err = fmt.Errorf("user pointer is nil")
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		dbUser := *userPtr
		bodyPtr, err := GetRequestData(c)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if bodyPtr == nil {
			err = fmt.Errorf("body pointer is nil")
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		body := *bodyPtr
		inputUserPtr, err := types.User{}.Hydrate(body)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if inputUserPtr == nil {
			err = fmt.Errorf("input user pointer is nil")
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		inputUser := *inputUserPtr
		newUserPtr, err := inputUser.Merge(dbUser, inputUser)
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		if newUserPtr == nil {
			err = fmt.Errorf("new user pointer is nil")
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}
		newUser := *newUserPtr
		err = newUser.PGUpdate()
		if err != nil {
			s.Error.Err(err)
			data["error"] = err.Error()
			return c.JSON(http.StatusInternalServerError, data)
		}

		data["msg"] = "ok"
		return c.JSON(http.StatusOK, data)
	}
}

func (s SettingsController) PostApiUserDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiUserDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		return nil
	}
}

func (s SettingsController) PostApiPolicyCreate() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiPolicyCreate"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		body, err := GetRequestData(c)
		if err != nil {
			return err
		}
		if body == nil {
			return fmt.Errorf("request is nil")
		}
		msi := *body
		values := make(map[string]string)
		values["name"] = ""
		values["role"] = ""
		values["resource"] = ""
		values["permission"] = ""
		values["isContent"] = ""
		if v, ok := msi["name"].(string); ok {
			values["name"] = v
		}
		if v, ok := msi["role"].(string); ok {
			values["role"] = v
		}
		if v, ok := msi["resource"].(string); ok {
			values["resource"] = v
		}
		if v, ok := msi["permission"].(string); ok {
			values["permission"] = v
		}
		policyPtr := acl.NewPolicy(values["name"], values["role"], values["resource"], values["permission"])
		if policyPtr == nil {
			fmt.Errorf("policy pointer is nil")
			s.Error.Err(err)
			return err
		}
		policy := *policyPtr
		err = policy.PGCreate()
		if err != nil {
			s.Error.Err(err)
			return err
		}
		return nil
	}
}

func (s SettingsController) PostApiPolicyEdit() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiPolicyEdit"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		return nil
	}
}

func (s SettingsController) PostApiPolicyDelete() echo.HandlerFunc {
	return func(c echo.Context) error {
		s.Error.Function = "PostApiPolicyDelete"
		s.Error.RequestUri = c.Request().RequestURI
		data, err := authenticateToken(c)
		if err != nil {
			if err.Error() == "bearer not found" {
				return c.JSON(http.StatusOK, data)
			}
			s.Error.Err(err)
			return c.JSON(http.StatusInternalServerError, data)
		}
		return nil
	}
}


func (c SettingsController) RegisterResources(e *echo.Echo) error {
	c.Error.Function = "GetUserDelete"
	
	view := e.Group("/settings")
	api := e.Group("/api")
	view.GET("", c.Get())
	view.GET("/user/create", c.GetUserCreate())
	view.GET("/user/edit/:id", c.GetUserEdit())
	view.GET("/user/delete/:id", c.GetUserDelete())
	view.GET("/role/create", c.GetRoleCreate())
	view.GET("/role/edit/:id", c.GetRoleEdit())
	view.GET("/role/edit/:id", c.GetRoleDelete())
	view.GET("/policy/create", c.GetPolicyCreate())
	view.GET("/policy/edit/:id", c.GetPolicyEdit())
	view.GET("/policy/delete/:id", c.GetPolicyDelete())

	api.POST("/user/create", c.PostApiUserCreate())
	api.POST("/role/create", c.PostApiRoleCreate())
	api.POST("/user/edit/:id", c.PostApiUserEdit())
	api.POST("/user/delete/:id", c.PostApiUserDelete())
	api.POST("/role/edit/:id", c.PostApiRoleEdit())
	api.POST("/role/delete/:id", c.PostApiRoleDelete())
	api.POST("/policy/create", c.PostApiPolicyCreate())
	api.POST("/policy/edit/:id", c.PostApiPolicyEdit())
	api.POST("/policy/delete/:id", c.PostApiPolicyDelete())

	resources := acl.Resources{}
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/user/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/user/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/user/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/location/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/location/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/location/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/role/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/role/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/role/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/policy/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/policy/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/settings/policy/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/user/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/user/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/user/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/location/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/location/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/location/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/role/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/role/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/role/delete",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/policy/create",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/policy/edit",
	})
	resources = append(resources, acl.Resource{
		Id: uuid.NewString(),
		URL: "/api/policy/delete",
	})

	adminRolePtr, err := acl.GetRole("admin")
	if err != nil {
		c.Error.Err(err)
		return err
	}
	var adminRole acl.Role
	if adminRolePtr != nil {
		adminRole = *adminRolePtr
		err = UpdateRole(adminRole.Id, resources)
		if err != nil {
			c.Error.Err(err)
			return err
		}
	}
	err = UpdateResources(resources)
	if err != nil {
		c.Error.Err(err)
		return err
	}
	err = UpdatePolicy("admin", resources)
	if err != nil {
		c.Error.Err(err)
		return err
	}
	return nil
}