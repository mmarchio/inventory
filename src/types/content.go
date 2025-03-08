package types

import (
	"context"
	"fmt"
	"inventory/src/db"
	"inventory/src/errors"
	"inventory/src/util"
	"strings"

	"github.com/jackc/pgx/v5"
)

type IContent interface {
	ToContent(context.Context) (*Content, error)
}

type Content struct {
	Attributes
	Content []byte `json:"content"`
	Errors map[string]errors.Error
}

func (c Content) Create(ctx context.Context, object IContent) *map[string]errors.Error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Create")
    }
	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		c.Errors = ce
	}
	e := errors.Error{
		File: "content.go",
		Package: "types",
		Function: "Create",
		Struct: "Content",
	}
	c.Errors["content:Create"] = e

	pg := db.PostgresClient{
		Ctx: ctx,
	}

	erp := pg.Open()
	if erp != nil {
		c.Errors["pg:Open"] = c.Errors["content:Create"]
		if erp != nil {
			ers := *erp
			c.Errors["pg:Open"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		}
		return &c.Errors
	}

	defer pg.Close()

	contentPtr, err := object.ToContent(ctx)
	if erp != nil {
		c.Errors["object:ToContent"] = c.Errors["content:Create"]
		if erp != nil {
			c.Errors["object:ToContent"].Err(ctx, fmt.Errorf("object interface error"))
		}
		return &c.Errors
	}

	if contentPtr == nil {
		c.Errors["content:Create"].Err(ctx, fmt.Errorf("content is nil"))
		return &c.Errors
	}

	content := *contentPtr
	if pg.Pgx == nil {
		c.Errors["content:Create"].Err(ctx, fmt.Errorf("pgx is nil"))
		return &c.Errors
	}
	pg.Tx, err = pg.Pgx.Begin(pg.Ctx)
	if err != nil {
		c.Errors["pg:begin"] = c.Errors["content:Create"]
		c.Errors["pg:begin"].Err(ctx, err)
		return &c.Errors
	}
	defer pg.Tx.Commit(pg.Ctx)
	columns := content.Columns(ctx)
	values := content.Values(ctx)
	q := fmt.Sprintf("INSERT INTO content (%s) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", columns)
	_, err = pg.Tx.Conn().Exec(
		pg.Ctx,
		q,
		values...
	)
	if err != nil {
		c.Errors["content:Create"].Err(ctx, err)
		rollbackErr := pg.Tx.Rollback(pg.Ctx)
		if rollbackErr != nil {
			c.Errors["content:create:rollback"] = e
			c.Errors["content:create:rollback"].Err(ctx, rollbackErr)
			return &c.Errors
		}
	}

	return nil
}

func (c Content) Columns(ctx context.Context) string {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Columns")
    }
	cols := []string{"id", "parent_id", "root_id", "created_at", "updated_at", "created_by", "owned", "name", "content_type", "content"}
	return fmt.Sprintf("%s", strings.Join(cols, ", "))
}

func (c Content) Values(ctx context.Context) []interface{} {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Values")
    }
	vals := []interface{}{
		c.Attributes.Id, 
		c.Attributes.ParentId, 
		c.Attributes.RootId,
		c.Attributes.CreatedAt.Unix(),
		c.Attributes.UpdatedAt.Unix(),
		c.Attributes.CreatedBy,
		c.Attributes.Owner,
		c.Attributes.Name,
		c.Attributes.ContentType,
		c.Content,
	}
	return vals
}

func (c Content) StringValues(ctx context.Context) []string {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Values")
    }
	vals := []string{
		c.Attributes.Id, 
		c.Attributes.ParentId, 
		c.Attributes.RootId,
		c.Attributes.CreatedAt.Format(FORMAT),
		c.Attributes.UpdatedAt.Format(FORMAT),
		c.Attributes.CreatedBy,
		c.Attributes.Owner,
		c.Attributes.Name,
		c.Attributes.ContentType,
		string(c.Content),
	}
	return vals
}

func (c Content) CreateMany(ctx context.Context, objects []Content) *map[string]errors.Error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:CreateMany")
    }
	pg := db.PostgresClient{
		Ctx: ctx,
	}

	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "CreateMany",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:CreateMany"] = e			
		c.Errors = ce

	}

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["content:CreateMany"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		return &c.Errors
	}

	defer pg.Close()
	var cvs []string
	baseString := "('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"
	var placeholders []string
	for _, object := range objects {
		objectValues := object.StringValues(ctx)
		ovcopy := []any{}
		for _, ov := range objectValues {
			ovcopy = append(ovcopy, ov)
		}
		placeholders = append(placeholders, fmt.Sprintf(baseString, ovcopy...))
		ovcopy = []any{}
		cvs = append(cvs, objectValues...)
	}
	q := fmt.Sprintf("INSERT INTO content (%s) VALUES %s", Content{}.Columns(ctx), strings.Join(placeholders, ", "))

	if pg.Pgx == nil {
		c.Errors["content:CreateMany"].Err(ctx, fmt.Errorf("pgx is nil"))
		return &c.Errors
	}
	var err error
	pg.Tx, err = pg.Pgx.Begin(pg.Ctx)
	if err != nil {
		c.Errors["pg:begin"] = c.Errors["content:CreateMany"]
		c.Errors["pg:begin"].Err(ctx, err)
		return &c.Errors
	}
	defer pg.Tx.Commit(pg.Ctx)
	_, err = pg.Tx.Conn().Exec(pg.Ctx, q)
	if err != nil {
		c.Errors["pg:tx:conn"] = c.Errors["content:CreateMany"]
		c.Errors["pg:tx:conn"].Err(ctx, err)
		rollbackErr := pg.Tx.Rollback(pg.Ctx)
		if rollbackErr != nil {
			c.Errors["pg:tx:rollback"] = c.Errors["content:CreateMany"]
			c.Errors["pg:tx:rollback"].Err(ctx, err)
			return &c.Errors
		}
	}

	return nil
}

func (c Content) ScanRow(rows pgx.Rows) error {
	debugBytes(rows.RawValues())
	// err := rows.Scan(&c)
	// if err != nil {
	// 	return err
	// }
	return nil
}

func (c Content) Read(ctx context.Context, id string) (*Content, *map[string]errors.Error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Read")
    }
	pg := db.PostgresClient{
		Ctx: ctx,
	}

	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "Read",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:Read"] = e			
		c.Errors = ce
	}

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["pg:Open"] = c.Errors["content:Read"]
		c.Errors["pg:Open"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		return nil, &c.Errors
	}
	defer pg.Close()

	rows, err := pg.Pgx.Query(pg.Ctx, "SELECT * FROM content WHERE id = $1", id)
	if err != nil {
		c.Errors["pgx:query"] = c.Errors["content:Read"]
		c.Errors["pgx:query"].Err(ctx, err)
		return nil, &c.Errors
	}
	if rows.Next() {
		err = rows.Scan(&c)
		if err != nil {
			c.Errors["rows:scan"] = c.Errors["content:Read"]
			c.Errors["rows:scan"].Err(ctx, err)
			return nil, &c.Errors
		}
	}

	return &c, nil
}

func (c Content) FindAll(ctx context.Context, t string) ([]Content, *map[string]errors.Error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:FindAll")
    }
	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "FindAll",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:FindAll"] = e			
		c.Errors = ce

	}

	pg := db.NewPostgresClient(ctx)

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["pg:Open"] = c.Errors["content:FindAll"]
		c.Errors["pg:Open"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		return nil, &c.Errors
	}
	defer pg.Close()
	rows, err := pg.Pgx.Query(pg.Ctx, "SELECT * FROM content WHERE content_type = $1", t)
	if err != nil {
		c.Errors["pgx:query"] = c.Errors["content:FindAll"]
		pq := c.Errors["pgx:query"]
		pq.Recoverable = true
		c.Errors["pgx:query"] = pq
		c.Errors["pgx:query"].Err(ctx, err)
		return nil, &c.Errors
	}
	//r := make([]Content, 0)
	// contents := make([]Content, 0)
	defer rows.Close()
	for rows.Next() {
		// content := Content{}
		debugBytes(rows.RawValues())
		// err = rows.Scan(&content)
		// if err != nil {
		// 	pg.Error.Err(ctx, err)
		// 	return nil, err
		// }
		// contents = append(contents, content)
	}
	// fmt.Printf("\nmsis: %#v\n", contents)
	return nil, nil
}

func debugBytes(b [][]byte) {
	for i, v := range b {
		fmt.Printf("\nrow %d: %s\n", i, string(v))
	} 
}

func (c Content) FindBy(ctx context.Context, jstring string) (*Content, *map[string]errors.Error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:FindBy")
    }

	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "SelectIn",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:SelectIn"] = e			
		c.Errors = ce
	}

	pg := db.NewPostgresClient(ctx)

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["pg:open"] = c.Errors["content:FindBy"]
		c.Errors["pg:open"].Err(ctx, ers["pg:Open"].Wrapper)
		return nil, &c.Errors
	}
	defer pg.Close()
	r := c
	rows, err := pg.Pgx.Query(pg.Ctx, "SELECT * FROM content WHERE content @> $1", jstring)
	if err != nil {
		c.Errors["pgx:query"] = c.Errors["content:FindBy"]
		c.Errors["pgx:query"].Err(ctx, err)
		return nil, &c.Errors
	}
	err = rows.Scan(&r)
	if err != nil {
		c.Errors["rows:scan"] = c.Errors["content:FindBy"]
		c.Errors["rows:scan"].Err(ctx, err)
		return nil, &c.Errors
	}
	return &r, nil
}

func (c Content) SelectIn(ctx context.Context, ids []string) ([]*Content, *map[string]errors.Error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:SelectIn")
    }

	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "SelectIn",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:SelectIn"] = e			
		c.Errors = ce
	}

	pg := db.NewPostgresClient(ctx)

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["pg:open"] = c.Errors["content:SelectIn"]
		c.Errors["pg:open"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		return nil, &c.Errors
	}
	defer pg.Close()

	q := fmt.Sprintf("SELECT * FROM content WHERE id IN ('%s')", strings.Join(ids, "', '"))
	rows, err := pg.Pgx.Query(pg.Ctx, q)
	if err != nil {
		c.Errors["pgx:query"] = c.Errors["content:SelectIn"]
		c.Errors["pgx:query"].Err(ctx, err)
		return nil, &c.Errors
	}
	contents := make([]*Content, 0)
	if rows.Next() {
		content := Content{}
		err = rows.Scan(&content)
		if err != nil {
			c.Errors["rows:scan"] = c.Errors["content:SelectIn"]
			c.Errors["rows:scan"].Err(ctx, err)
			return nil, &c.Errors
		}
		contents = append(contents, &content)
	}
	return contents, nil
}

func (c Content) Update(ctx context.Context, object IContent) *map[string]errors.Error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Update")
    }

	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "Update",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:Update"] = e			
		c.Errors = ce
	}

	pg := db.NewPostgresClient(ctx)

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["pg:open"] = c.Errors["content:Update"]
		c.Errors["pg:open"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		return &c.Errors
	}
	defer pg.Close()
	erp = c.Delete(ctx, c.Attributes.Id)
	if erp != nil {
		ers := *erp
		c.Errors["delete"] = c.Errors["content:Update"]
		c.Errors["delete"].Err(ctx, ers["content:Delete"].Wrapper)
		return &c.Errors
	}
	erp = c.Create(ctx, object)
	if erp != nil {
		ers := *erp
		c.Errors["create"] = c.Errors["content:Update"]
		c.Errors["create"].Err(ctx, ers["content:Create"].Wrapper)
		return &c.Errors
	}
	// q := fmt.Sprintf("UPDATE content SET %s WHERE id = ?", c.UpdateString())
	// _, values := c.Values()
	// _, err = pg.Sqlx.Query(q, c.ContentType, values)
	// if err != nil {
	// 	return err
	// }
	return nil
}

func (c Content) Delete(ctx context.Context, id string) *map[string]errors.Error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:content.go:Content:Delete")
    }

	if c.Errors == nil {
		ce := make(map[string]errors.Error)
		e := errors.Error{
			File: "content.go",
			Package: "types",
			Function: "Delete",
			Struct: "Content",
		}
		e.GetCtxTrace(ctx)
		ce["content:Delete"] = e			
		c.Errors = ce
	}

	pg := db.NewPostgresClient(ctx)

	erp := pg.Open()
	if erp != nil {
		ers := *erp
		c.Errors["pg:open"] = c.Errors["content:delete"]
		c.Errors["pg:open"].Err(ctx, ers["PostgresClient:Open"].Wrapper)
		return err
	}
	defer pg.Close()
	_, err := pg.Pgx.Query(ctx, "DELETE FROM content WHERE id = $1", id)
	if err != nil {
		c.Errors["pgx:query"] = c.Errors["content:Delete"]
		c.Errors["pgx:query"].Err(ctx, err)
		return &c.Errors
	}
	return nil
}
