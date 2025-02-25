package login

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

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
    Username string `json:"username"`
    Password string `json:"password"`
}

func (c Credentials) MSIHydrate(msi map[string]interface{}) (Credentials, error) {
    r := Credentials{}
    if v, ok := msi["username"].(string); ok {
        r.Username = v
    }
    if v, ok := msi["password"].(string); ok {
        r.Password = v
    }
    return r, nil
}

func (c Credentials) ToMSI() (map[string]interface{}, error) {
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		return r, err
	}
	return r, nil
}

func (c Credentials) IsDocument() bool {
    return true
}

type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

func Login(username, userValue, dbValue string) (*http.Cookie, error) {
    creds := Credentials{
        Username: username,
    }
    auth := VerifyPassword(userValue, dbValue)
    if !auth {
        err := fmt.Errorf("password does not match %s:%s", userValue, dbValue)
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
        return nil, err
    }

    test, err := decodeJWT(tokenString, []byte("secret"))
    if err != nil {
        return nil, err
    }
    msi := make(map[string]interface{})
    b, err := json.Marshal(test)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(b, &msi)
    if err != nil {
        return nil, err
    }

    r := &http.Cookie{
        Name:    "token",
        Value:   tokenString,
        Expires: expirationTime,
    }
    return r, nil
}

func ExtendToken(tokenString string, secret []byte) (*string, error) {
    claims, err := decodeJWT(tokenString, secret)
    if err != nil {
        return nil, err
    }
    b, err := json.Marshal(claims)
    if err != nil {
        return nil, err
    }
    msi := make(map[string]interface{})
    err = json.Unmarshal(b, &msi)
    if err != nil {
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
    token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
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

func HashPassword(password string) (string, error) {
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
