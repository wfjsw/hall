DATE:=$(shell date -u '+%F %T')
VERSION:=$(shell git describe --tags --dirty --broken)

zh: 
	go mod download
	go mod vendor
	go build -v -o hall -trimpath -tags lang_zh -ldflags='-s -w -X "main.BUILDDATE=$(DATE)" -X "main.VERSION=$(VERSION)"' .

en: 
	go mod download
	go mod vendor
	go get -v -o hall -trimpath -tags lang_en -ldflags='-s -w -X "main.BUILDDATE=$(DATE)" -X "main.VERSION=$(VERSION)"' .

clean:
	rm hall

dist-clean:
	rm hall
	rm -rf vendor
