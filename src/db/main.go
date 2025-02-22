package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

type IDocument interface {
    IsDocument() bool
    ToMSI() (map[string]interface{}, error)
}

// Document represents a basic structure for storing data in Redis
type Document struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Value string `json:"value"`
    ContentID string `json:"contentId"`
}

type JSONDocuments []IDocument

// RedisClient wraps the Redis client and provides CRUD operations
type RedisClient struct {
    client *redis.Client
}

type RedisConfig struct {
    Domain string
    Port int32
    Password string
}

// NewRedisClient initializes a new Redis client
func NewRedisClient() (*RedisClient, error) {
    domain := os.Getenv("REDIS_DOMAIN")
    port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
    password := os.Getenv("REDIS_PASSWORD")
    if err != nil {
        return nil, err
    }
    rdb := redis.NewClient(&redis.Options{
        Addr:     fmt.Sprintf("%s:%d", domain, port),
        Password: password, // no password set
        DB:       0,  // use default DB
    })

    return &RedisClient{client: rdb}, nil
}

func (i Document) MarshalBinary() ([]byte, error) {
    return json.Marshal(i)
}

//CreateJSONDocument saves a new JSON Document in redis
func (r *RedisClient) CreateJSONDocument(doc IDocument, key, path string, overwrite bool) error {
    ctx := context.Background()
    redisResponseString, err := r.ReadJSONDocument(key, path)
    if err != nil {
        return err
    }
    smsi := make([]map[string]interface{}, 0)
    if !overwrite {
        if redisResponseString != nil {
            responseString := *redisResponseString
            if responseString != "" && responseString != "{}" {
                if responseString[0] == '{' {
                    responseString = fmt.Sprintf("[%s]", responseString)
                }
                err = json.Unmarshal([]byte(responseString), &smsi)
                if err != nil {
                    return err
                }
            }
            msi, err := doc.ToMSI()
            if err != nil {
                return err
            }
            smsi = append(smsi, msi)
        }
        _, err = r.client.JSONSet(ctx, key, path, smsi).Result()
        if err != nil {
            return err
        }
    } else {
        _, err = r.client.JSONSet(ctx, key, path, doc).Result()
        if err != nil {
            return err
        }
    }
    return nil
}

// CreateDocument saves a new document in Redis
func (r *RedisClient) CreateDocument(doc *Document) error {
    err := r.client.Set(ctx, doc.ID, doc, 0).Err()
    if err != nil {
        return err
    }
    return nil
}

// ReadJSONDocument retrieves a JSON document from redis by key
func (r *RedisClient) ReadJSONDocument(key, path string) (*string, error) {
    ctx := context.Background()
    val, err := r.client.JSONGet(ctx, key, path).Result()
    if err != nil {
        return nil, err
    }
    return &val, nil
}

// ReadDocument retrieves a document from Redis by ID
func (r *RedisClient) ReadDocument(id string) (*Document, error) {
    val, err := r.client.Get(ctx, id).Result()
    if err != nil {
        return nil, err
    }

    doc := &Document{}
    err = json.Unmarshal([]byte(val), doc)
    if err != nil {
        return nil, err
    }

    return doc, nil
}

// UpdateJSONDocument updates an existing JSON document in redis
func (r *RedisClient) UpdateJSONDocument(i IDocument, key, path string) error {
    return r.CreateJSONDocument(i, key, path, true)
}

// UpdateDocument updates an existing document in Redis
func (r *RedisClient) UpdateDocument(doc *Document) error {
    err := r.client.Set(ctx, doc.ID, doc, 0).Err()
    if err != nil {
        return err
    }
    return nil
}

// DeleteJSONDocument deletes a JSON document from redis by key
func (r *RedisClient) DeleteJSONDocument(key, path string) error {
    ctx := context.Background()
    _, err := r.client.JSONDel(ctx, key, path).Result()
    if err != nil {
        return err
    }
    return nil
}

// DeleteDocument deletes a document from Redis by ID
func (r *RedisClient) DeleteDocument(id string) error {
    err := r.client.Del(ctx, id).Err()
    if err != nil {
        return err
    }
    return nil
}

func main(){}