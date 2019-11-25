package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/gobuffalo/packr/v2"
	_ "github.com/lib/pq"
	migrate "github.com/rubenv/sql-migrate"
)

func NewTest(cfg *Config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.String())
	if err != nil {
		return nil, err
	}

	if err := Migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

func New(cfg *Config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.String())
	if err != nil {
		return nil, err
	}

	// Set the maximum number of concurrently open connections to 5.
	// Setting this to less than or equal to 0 will mean there is no
	// maximum limit (which is also the default setting).
	db.SetMaxOpenConns(5)

	// Set the maximum number of concurrently idle connections to 5.
	// Setting this to less than or equal to 0 will mean that no idle
	// connections are retained.
	db.SetMaxIdleConns(5)

	// Set the maximum lifetime of a connection to 1 hour. Setting it to 0
	// means that there is no maximum lifetime and the connection is reused
	// forever (which is the default behavior).
	db.SetConnMaxLifetime(time.Hour)

	// Ensure that the connection is really established.
	for i := 0; i < 3; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		fmt.Println("retrying db connection...")
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		return nil, err
	}

	if err := Migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

func Migrate(db *sql.DB) error {
	// Perform migrations.
	// - rename the default gorp_migrations table to migrations.
	migrate.SetTable("migrations")
	migrations := &migrate.PackrMigrationSource{
		Box: packr.New("migrations", "./migrations"),
	}
	res, err := migrate.Exec(db, "postgres", migrations, migrate.Up)
	if err != nil {
		return err
	}
	fmt.Printf("Applied migrations: %d\n", res)
	return nil
}

func Setup() (*sql.DB, error) {
	cfg, err := NewConfig()
	if err != nil {
		return nil, err
	}
	db, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return db, nil
}
