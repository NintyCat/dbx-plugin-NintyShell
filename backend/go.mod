module github.com/NintyCat/dbx-plugin-NintyShell

go 1.22

require (
	github.com/creack/pty v1.1.24
	github.com/pkg/sftp v1.13.7
	github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk v0.1.0
	golang.org/x/crypto v0.32.0
	golang.org/x/sys v0.30.0
)

require github.com/kr/fs v0.1.0 // indirect

replace github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk => ./third-party/dbx-plugin-sdk
