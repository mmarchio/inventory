package login

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type IDocument interface {
	IsDocument() bool
}

var jwtKey = []byte(os.Getenv("JWT_SECRET"))
var oauth2Config = &oauth2.Config{
	ClientID:     os.Getenv("OAUTH2_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH2_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("OAUTH2_REDIRECT_URL"),
	Endpoint:     google.Endpoint,
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
}

type Credentials struct {
	types.Attributes
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c Credentials) New(ctx context.Context) (*Credentials,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:New")
	}
	e := errors.Error{}
	credentials := c
	attributesPtr, err := c.Attributes.New(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		e.Err(ctx, err)
		return nil, err
	}

	credentials.Attributes = *attributesPtr
	return &credentials, nil
}

func (c Credentials) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:ToContent")
	}
	e := errors.Error{}
	content := types.Content{}
	content.Id = c.Attributes.Id
	jbytes, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Credentials) PGRead(ctx context.Context) (*Credentials,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:PGRead")
	}
	e := errors.Error{}
	contentPtr, err := types.Content{}.Read(ctx, c.Attributes.Id)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return nil, err
	}
	content := *contentPtr
	credentials := c
	err = json.Unmarshal(content.Content, &credentials)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &credentials, nil
}

func (c Credentials) PGCreate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:PGCreate")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return err
	}
	content := *contentPtr
	return content.Create(ctx, c)
}

func (c Credentials) PGUpdate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:PGUpdate")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return err
	}
	content := *contentPtr
	return content.Update(ctx, c)
}

func (c Credentials) PGDelete(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:PGDelete")
	}
	err := types.Content{}.Delete(ctx, c.Attributes.Id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Credentials) FindBy(ctx context.Context, jstring string) (*Credentials,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:FindBy")
	}
	e := errors.Error{}
	contentPtr, err := types.Content{}.FindBy(ctx, jstring)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content pointer is nil")
		e.Err(ctx, err)
		return nil, err
	}
	content := *contentPtr
	credentials := c
	err = json.Unmarshal(content.Content, &credentials)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &credentials, nil
}

func (c Credentials) MSIHydrate(ctx context.Context, msi map[string]interface{}) (Credentials,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:MSIHydrate")
	}
	r := Credentials{}
	if v, ok := msi["username"].(string); ok {
		r.Username = v
	}
	if v, ok := msi["password"].(string); ok {
		r.Password = v
	}
	return r, nil
}

func (c Credentials) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:ToMSI")
	}
	e := errors.Error{}
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	return r, nil
}

func (c Credentials) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Credentials:IsDocument")
	}
	return true
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(ctx context.Context, username, userValue, dbValue string) (*http.Cookie,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:Login")
	}
	e := errors.Error{}
	creds := Credentials{
		Username: username,
	}
	auth := VerifyPassword(userValue, dbValue)
	if !auth {
		err := fmt.Errorf("password does not match %s:%s", userValue, dbValue)
		e.Err(ctx, err)
		return nil, err
	}
	expirationTime := time.Now().Add(2 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}

	test, err := decodeJWT(ctx, tokenString, []byte("secret"))
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	msi := make(map[string]interface{})
	b, err := json.Marshal(test)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	err = json.Unmarshal(b, &msi)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}

	r := &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	}
	return r, nil
}

func ExtendToken(ctx context.Context, tokenString string, secret []byte) (*string,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "login:login.go:ExtendToken")
	}
	e := errors.Error{}
	claims, err := decodeJWT(ctx, tokenString, secret)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	b, err := json.Marshal(claims)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	msi := make(map[string]interface{})
	err = json.Unmarshal(b, &msi)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	expirationTime := time.Now().Add(15 * time.Minute)
	if v, ok := msi["username"].(string); ok {
		newClaims := &Claims{
			Username: v,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
		newTokenString, err := token.SignedString(jwtKey)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		return &newTokenString, nil
	}

	return nil, nil
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{},*map[string]errors.Error)
 {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(15 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func OAuth2CallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := oauth2Config.Exchange(oauth2.NoContext, code)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	client := oauth2Config.Client(oauth2.NoContext, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	userInfo := map[string]interface{}{}
	json.NewDecoder(resp.Body).Decode(&userInfo)
	json.NewEncoder(w).Encode(userInfo)
}

func HashPassword(password string) (string,*map[string]errors.Error)
 {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(hash)
	}
	return err == nil
}

func decodeJWT(ctx context.Context, tokenString string, secretKey []byte) (jwt.MapClaims, *map[string]errors.Error)
 {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, *map[string]errors.Error)
 {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	e := errors.Error{}
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
