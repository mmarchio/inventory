package login

import (
    "net/http"
    "strings"

    "github.com/dgrijalva/jwt-go"
)

func JWTMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        tokenStr := strings.Split(authHeader, "Bearer ")[1]
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

        next.ServeHTTP(w, r)
    })
}
