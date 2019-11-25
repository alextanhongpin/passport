package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"

	"github.com/ory/dockertest"
)

// // Usage:
// func TestMain(m *testing.M) {
//         database.TestMain(m)
// }
//
// // Use.
// db := database.DB()

var db *sql.DB

func TestConfig(port int) *Config {
	return &Config{
		Password: "secret",
		User:     "root",
		Database: "test",
		Host:     "localhost",
		Port:     port,
	}
}

func TestMain(m *testing.M) {
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run("postgres", "12.0-alpine", []string{"POSTGRES_DB=test", "POSTGRES_PASSWORD=secret", "POSTGRES_USER=root"})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		var err error
		port, err := strconv.Atoi(resource.GetPort("5432/tcp"))
		if err != nil {
			return err
		}
		db, err = NewTest(TestConfig(port))
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			if err := pool.Purge(resource); err != nil {
				log.Fatalf("Could not purge resource: %s", err)
			}
		}
		os.Exit(1)
	}()

	code := m.Run()
	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func DB() *sql.DB {
	return db
}
