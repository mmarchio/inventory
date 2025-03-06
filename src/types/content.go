package types

import (
	"context"
	"fmt"
	"inventory/src/db"
	"inventory/src/errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

type IContent interface {
	ToContent(context.Context) (*Content, error)
}

type Content struct {
	Attributes
	Content []byte `json:"content"`
}

func (c Content) Create(ctx context.Context, object IContent) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:Create")
    }
	e := errors.Error{}
	pg := db.PostgresClient{
		Ctx: ctx,
	}

	err := pg.Open()
	if err != nil {
        e.Err(ctx, err)
		return err
	}

	defer pg.Close()

	contentPtr, err := object.ToContent(ctx)
	if err != nil {
        e.Err(ctx, err)
		return err
	}

	if contentPtr == nil {
		err = fmt.Errorf("content pointer is nil")
        e.Err(ctx, err)
		return err
	}

	content := *contentPtr
	if pg.Pgx == nil {
		err = fmt.Errorf("pgx is nil")
        e.Err(ctx, err)
		panic(err.Error())
	}
	pg.Tx, err = pg.Pgx.Begin(pg.Ctx)
	if err != nil {
        e.Err(ctx, err)
		return err
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
        e.Err(ctx, err)
		rollbackErr := pg.Tx.Rollback(pg.Ctx)
		if rollbackErr != nil {
			e.Err(ctx, rollbackErr)
			return rollbackErr
		}
	}

	return nil
}

func (c Content) Columns(ctx context.Context) string {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:Columns")
    }
	cols := []string{"id", "parent_id", "root_id", "created_at", "updated_at", "created_by", "owned", "name", "content_type", "content"}
	return fmt.Sprintf("%s", strings.Join(cols, ", "))
}

func (c Content) Values(ctx context.Context) []interface{} {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:Values")
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

func (c Content) CreateMany(ctx context.Context, objects []Content) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:CreateMany")
    }
	e := errors.Error{}
	pg := db.PostgresClient{
		Ctx: ctx,
	}

	err := pg.Open()
	if err != nil {
        e.Err(ctx, err)
		return err
	}

	defer pg.Close()
	var cvs []any
	baseString := "($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)"
	var placeholders []string
	for i, object := range objects {
		var ctr int64
		if i == 0 {
			ctr = 0
		} else {
			ctr = int64(i)*int64(10)
		}
		var vals []int64
		for i := 1; i < 11; i++ {
			vals = append(vals, int64(ctr)+int64(i))
		}
		placeholders = append(placeholders, fmt.Sprintf(baseString, vals))
		objectValues := object.Values(ctx)
		cvs = append(cvs, objectValues...)
	}
	q := fmt.Sprintf("INSERT INTO content (%s) VALUES %s", Content{}.Columns(ctx), strings.Join(placeholders, ", "))
	fmt.Printf("\n%s\n", q)

	if pg.Pgx == nil {
		err = fmt.Errorf("pgx is nil")
        e.Err(ctx, err)
		panic(err.Error())
	}
	pg.Tx, err = pg.Pgx.Begin(pg.Ctx)
	if err != nil {
        e.Err(ctx, err)
		return err
	}
	defer pg.Tx.Commit(pg.Ctx)
	_, err = pg.Tx.Conn().Exec(
		pg.Ctx,
		q,
		cvs...
	)
	if err != nil {
        e.Err(ctx, err)
		rollbackErr := pg.Tx.Rollback(pg.Ctx)
		if rollbackErr != nil {
			e.Err(ctx, rollbackErr)
			return rollbackErr
		}
	}

	return nil
}

func (c Content) ScanRow(rows pgx.Rows) error {
	err := rows.Scan(&c)
	if err != nil {
		return err
	}
	return nil
}

func (c Content) Read(ctx context.Context, id string) (*Content, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:Read")
    }
	pg := db.PostgresClient{
		Ctx: ctx,
	}
	err := pg.Open()
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	defer pg.Close()

	rows, err := pg.Pgx.Query(pg.Ctx, "SELECT * FROM content WHERE id = $1", id)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	if rows.Next() {
		err = rows.Scan(&c)
		if err != nil {
			pg.Error.Err(ctx, err)
			return nil, err
		}
	}

	return &c, nil
}

func (c Content) FindAll(ctx context.Context, t string) ([]Content, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:FindAll")
    }
	pg, err := db.NewPostgresClient(ctx)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	err = pg.Open()
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	defer pg.Close()
	rows, err := pg.Pgx.Query(pg.Ctx, "SELECT * FROM content WHERE content_type = $1", t)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	r := make([]Content, 0)
	for rows.Next() {
		content := Content{}
		err = rows.Scan(&content)
		if err != nil {
			pg.Error.Err(ctx, err)
			return nil, err
		}
		r = append(r, content)
	}
	return r, nil
}

func (c Content) FindBy(ctx context.Context, jstring string) (*Content, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:FindBy")
    }
	pg, err := db.NewPostgresClient(ctx)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	r := c
	rows, err := pg.Pgx.Query(pg.Ctx, "SELECT * FROM content WHERE content @> $1", jstring)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	err = rows.Scan(&r)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	return &r, nil
}

func (c Content) SelectIn(ctx context.Context, ids []string) ([]*Content, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:SelectIn")
    }
	pg, err := db.NewPostgresClient(ctx)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	err = pg.Open()
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	defer pg.Close()

	q := fmt.Sprintf("SELECT * FROM content WHERE id IN ('%s')", strings.Join(ids, "', '"))
	rows, err := pg.Pgx.Query(pg.Ctx, q)
	if err != nil {
		pg.Error.Err(ctx, err)
		return nil, err
	}
	contents := make([]*Content, 0)
	if rows.Next() {
		content := Content{}
		err = rows.Scan(&content)
		if err != nil {
			pg.Error.Err(ctx, err)
			return nil, err
		}
		contents = append(contents, &content)
	}
	return contents, nil
}

func (c Content) Update(ctx context.Context, object IContent) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:Update")
    }
	pg := db.PostgresClient{
		Ctx: context.Background(),
	}
	err := pg.Open()
	if err != nil {
		pg.Error.Err(ctx, err)
		return err
	}
	defer pg.Close()
	err = c.Delete(ctx, c.Attributes.Id)
	if err != nil {
		pg.Error.Err(ctx, err)
		return err
	}
	err = c.Create(ctx, object)
	if err != nil {
		pg.Error.Err(ctx, err)
		return err
	}
	// q := fmt.Sprintf("UPDATE content SET %s WHERE id = ?", c.UpdateString())
	// _, values := c.Values()
	// _, err = pg.Sqlx.Query(q, c.ContentType, values)
	// if err != nil {
	// 	return err
	// }
	return nil
}

func (c Content) Delete(ctx context.Context, id string) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:content.go:Content:Delete")
    }
	pg := db.PostgresClient{
		Ctx: context.Background(),
	}
	err := pg.Open()
	if err != nil {
		pg.Error.Err(ctx, err)
		return err
	}
	defer pg.Close()
	_, err = pg.Sqlx.Query("DELETE FROM content WHERE id = $1", id)
	if err != nil {
		pg.Error.Err(ctx, err)
		return err
	}
	return err
}
