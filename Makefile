
enroll: enroll.go
	GOOS=linux GOARCH=amd64 go build -o $@ enroll.go
