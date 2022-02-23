module github.com/wfjsw/hall

go 1.17

require (
	github.com/dyson/certman v0.2.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/pkg/errors v0.9.1
	github.com/wfjsw/go-proxy-protocol v0.0.0-20200504195738-a5636b1a5b3c
	github.com/wfjsw/hall/blobstore v0.0.0-00010101000000-000000000000
	github.com/wfjsw/hall/cryptstate v0.0.0-00010101000000-000000000000
	github.com/wfjsw/hall/htmlfilter v0.0.0-00010101000000-000000000000
	github.com/wfjsw/hall/logtarget v0.0.0-00010101000000-000000000000
	github.com/wfjsw/hall/mumbleproto v0.0.0-00010101000000-000000000000
	github.com/wfjsw/hall/packetdata v0.0.0-00010101000000-000000000000
	github.com/wfjsw/hall/sessionpool v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20211216030914-fe4d6282115f
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	google.golang.org/protobuf v1.27.1
	gorm.io/driver/sqlite v1.2.6
	gorm.io/gorm v1.22.3
)

require (
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.4 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/wfjsw/hall/cryptstate/ocb2 v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
)

replace github.com/wfjsw/hall/blobstore => ./blobstore

replace github.com/wfjsw/hall/cryptstate/ocb2 => ./cryptstate/ocb2

replace github.com/wfjsw/hall/cryptstate => ./cryptstate

replace github.com/wfjsw/hall/htmlfilter => ./htmlfilter

replace github.com/wfjsw/hall/logtarget => ./logtarget

replace github.com/wfjsw/hall/mumbleproto => ./mumbleproto

replace github.com/wfjsw/hall/packetdata => ./packetdata

//replace github.com/wfjsw/hall/replacefile => ./replacefile

replace github.com/wfjsw/hall/sessionpool => ./sessionpool
