module github.com/NintyCat/dbx-plugin-NintyShell

go 1.25.0

require (
	github.com/aymanbagabas/go-pty v0.2.3
	github.com/creack/pty v1.1.24
	github.com/pkg/sftp v1.13.9
	github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk v0.1.0
	golang.org/x/crypto v0.51.0
	golang.org/x/sys v0.44.0
)

require (
	github.com/kr/fs v0.1.0 // indirect
	github.com/u-root/u-root v0.16.0 // indirect
)

replace github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk => ./third-party/dbx-plugin-sdk
