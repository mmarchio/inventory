package db

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/util"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
    _ "github.com/jackc/pgx/v5/stdlib"
    _ "github.com/lib/pq"
    "database/sql"
    _ "database/sql/driver"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

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
    smsi := make([]map[string]interface{}, 0)
    if !overwrite {
        redisResponseString, err := r.ReadJSONDocument(key, path)
        if errors.ErrOrNil(ctx, redisResponseString, err) != nil {
            return err
        }
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
    
        _, err = r.client.JSONSet(ctx, key, path, smsi).Result()
        if err != nil {
            return err
        }
    } else {
        _, err := r.client.JSONSet(ctx, key, path, doc).Result()
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

type PostgresClient struct {
    Pgx *pgx.Conn
    Sqlx *sql.DB
    Ctx context.Context
    Tx pgx.Tx
    Error errors.Error
}

func NewPostgresClient(ctx context.Context) (*PostgresClient, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "db:main.go:NewPostgresClient")
    }
    pg := PostgresClient{
        Ctx: ctx,
    }
    return &pg, nil
}

func (c *PostgresClient) Open() error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "db:main.go:PostgresClient:Open")
    }
	conn, err := pgx.Connect(c.Ctx, os.Getenv("POSTGRES_URL"))
	if err != nil {
        c.Error.Err(c.Ctx, err)
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
    c.Pgx = conn
    // host := "localhost"
    // port := 5432
    // user := "pguser"
    // password := "pguser"
    // dbname := "inventory_v2"
    // psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
    // "password=%s dbname=%s sslmode=disable",
    // host, port, user, password, dbname)

    // conn, err := sql.Open("postgres", psqlInfo)
    // if err != nil {
    //     fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
    //     os.Exit(1)
    // }
    // c.Sqlx = conn
    return err
}

func (c PostgresClient) Close() error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "db:main.go:PostgresClient:Close")
    }
    err := c.Pgx.Close(c.Ctx)
    if err != nil {
        c.Error.Err(ctx, err)
        return err
    }
    return nil
}

func (c PostgresClient) Commit(tx pgx.Tx) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "db:main.go:PostgresClient:Commit")
    }
    err := tx.Conn().Close(c.Ctx)
    if err != nil {
        c.Error.Err(ctx, err)
        return err
    }
    return nil
}

func (c PostgresClient) Query(ctx context.Context, q string, rs pgx.RowScanner) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "db:main.go:PostgresClient:Open")
    }
    err := c.Open()
    if err != nil {
        c.Error.Err(ctx, err)
        return err
    }
    // txo := pgx.TxOptions{}
    // tx, err := c.Sqlx.BeginTx(c.Ctx, txo)
    // if err != nil {
    //     return err
    // }
    // defer c.Commit(tx)

    // defer func() {
    //     if err != nil {
    //         tx.Rollback(context.TODO())
    //     } else {
    //         tx.Commit(context.TODO())
    //     }
    // }()
    // row, err := tx.Query(context.TODO(), q)
    // if err != nil {
    //     return err
    // }
    // return rs.ScanRow(row) 
    return nil
}

func main(){}