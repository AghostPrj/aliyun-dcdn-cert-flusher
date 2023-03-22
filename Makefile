build : getDep clean amd64 arm64

getDep:
	go get -v -t -d ./...


clean :
	rm -rf target; go clean

amd64 :
	go clean; env GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags=-static" \
		-o target/linux-amd64/aliyun-dcdn-cert-flusher ./cmd/aliyun-dcdn-cert-flusher


arm64 :
	go clean; env GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -extldflags=-static" \
		-o target/linux-arm64/aliyun-dcdn-cert-flusher ./cmd/aliyun-dcdn-cert-flusher

