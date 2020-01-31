ifeq ($(ENV),)
	ENV := development
endif
-include .env
-include .env.${ENV}
export

DATABASE_CONFIG := database/dbconfig.yml

start: up generate
	@go run main.go

generate:
	@go generate

test:
	@go test -v ./...

install:
	# For packaging .sql files when building binary.
	@go get -u github.com/gobuffalo/packr/v2/packr2
	# For migrations.
	@go get -v github.com/rubenv/sql-migrate/...
	# To cleanup database after running test.
	@go get gopkg.in/khaiql/dbcleaner.v2

up:
	@docker-compose up -d

down:
	@docker-compose down

# https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
#
sql-%:
	@mkdir -p database/migrations
	@sql-migrate new -config=${DATABASE_CONFIG} -env="${ENV}" $* 

migrate:
	@sql-migrate up -config ${DATABASE_CONFIG} -env="${ENV}"

rollback:
	@sql-migrate down -config ${DATABASE_CONFIG} -env="${ENV}"


build:
	# TODO: Run packr2 before building the go binary.

clean:
	@rm -rf ./tmp
	@packr2 clean
