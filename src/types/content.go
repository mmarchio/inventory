package types

import (
	"context"
	"fmt"
	"inventory/src/db"
	"strings"

	"github.com/jackc/pgx/v5"
)

type IContent interface {
	ToContent() (*Content, error)
}

type Content struct {
	Attributes
	Content []byte `json:"content"`
}

func (c Content) Create(object IContent) error {
	pg := db.PostgresClient{
		Ctx: context.Background(),
	}

	err := pg.Open()
	if err != nil {
		return err
	}

	//defer pg.Close()

	contentPtr, err := object.ToContent()
	if err != nil {
		return err
	}

	if contentPtr == nil {
		return fmt.Errorf("content pointer is nil")
	}

	content := *contentPtr
	_, vals := c.Values()
	newVals := make([]interface{}, 0)
	newVals = append(newVals, vals...)
	if pg.Pgx == nil {
		panic("sqlx is nil")
	}
	_, err = pg.Pgx.Exec(
		pg.Ctx,
		"INSERT INTO content (id, parent_id, root_id, created_at, updated_at, created_by, owned, name, content_type, content) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
		content.Attributes.Id, 
		content.Attributes.ParentId, 
		content.Attributes.RootId,
		content.Attributes.CreatedAt.Format(FORMAT),
		content.Attributes.UpdatedAt.Format(FORMAT),
		content.Attributes.CreatedBy,
		content.Attributes.Owner,
		content.Attributes.Name,
		content.Attributes.ContentType,
		content.Content,
	)
	if err != nil {
		return err
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

func (c Content) Read(id string) (*Content, error) {
	pg := db.PostgresClient{
		Ctx: context.Background(),
	}
	err := pg.Open()
	if err != nil {
		return nil, err
	}
	defer pg.Close()

	rows, err := pg.Sqlx.Query("SELECT * FROM content WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	err = rows.Scan(&c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (c Content) Update() error {
	pg := db.PostgresClient{
		Ctx: context.Background(),
	}
	err := pg.Open()
	if err != nil {
		return err
	}
	defer pg.Close()
	q := fmt.Sprintf("UPDATE ? SET %s WHERE id = ?", c.UpdateString())
	_, values := c.Values()
	_, err = pg.Sqlx.Query(q, c.ContentType, values)
	if err != nil {
		return err
	}
	return nil
}

func (c Content) UpdateString() string {
	cols := c.Columns()
	var s []string
	for _, col := range cols {
		s = append(s, fmt.Sprintf("%s = ?", col))
	}
	return strings.Join(s, ", ")
}

func (c Content) Delete(id string) error {
	pg := db.PostgresClient{
		Ctx: context.Background(),
	}
	err := pg.Open()
	if err != nil {
		return err
	}
	defer pg.Close()
	_, err = pg.Sqlx.Query("DELETE FROM ? WHERE id = ?", c.ContentType, id)
	if err != nil {
		return err
	}
	return err
}

func (c Content) Columns() []string {
	cols := c.Attributes.Columns()
	cols = append(cols, "content")
	return cols
}

func (c Content) Values() (string, []interface{}) {
	vals := c.Attributes.Values()
	vals = append(vals, c.Content)
	l := len(vals)
	var s []string
	for i := 0; i < l; i++ {
		s = append(s, "?")
	}
	return strings.Join(s, ", "), vals
}