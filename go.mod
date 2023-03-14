module github.com/tillitis/tkey-verification

go 1.19

require (
	github.com/spf13/pflag v1.0.5
	// TODO there is not yet any v0.0.5 tag! the following was accomplished
	// by: go get github.com/tillitis/tillitis-key1-apps@integration
	github.com/tillitis/tillitis-key1-apps v0.0.5-0.20230314120345-a06e83d1553f
	go.bug.st/serial v1.5.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/creack/goselect v0.1.2 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
)
