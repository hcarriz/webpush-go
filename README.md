# webpush-go

[![Go Report Card](https://goreportcard.com/badge/github.com/hcarriz/webpush-go/v2)](https://goreportcard.com/report/github.com/hcarriz/webpush-go/v2)
[![GoDoc](https://godoc.org/github.com/hcarriz/webpush-go/v2?status.svg)](https://godoc.org/github.com/hcarriz/webpush-go/v2)

Web Push API Encryption with VAPID support.

```bash
go get -u github.com/hcarriz/webpush-go/v2
```

> This project is a fork of [github.com/SherClockHolmes/webpush-go/v2](https://github.com/SherClockHolmes/webpush-go/v2/)

## Example

For a full example, refer to the code in the [example](example/) directory.

```go
package main

import (
	"encoding/json"

	webpush "github.com/hcarriz/webpush-go/v2"
)

func main() {
	// Decode subscription
	s := &webpush.Subscription{}
	json.Unmarshal([]byte("<YOUR_SUBSCRIPTION>"), s)

	// Send Notification
	resp, err := webpush.SendNotification([]byte("Test"), s, &webpush.Options{
		Subscriber:      "example@example.com",
		VAPIDPublicKey:  "<YOUR_VAPID_PUBLIC_KEY>",
		VAPIDPrivateKey: "<YOUR_VAPID_PRIVATE_KEY>",
		TTL:             30,
	})
	if err != nil {
		// TODO: Handle error
	}
	defer resp.Body.Close()
}
```

### Generating VAPID Keys

Use the helper method `GenerateVAPIDKeys` to generate the VAPID key pair.

```golang
privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
if err != nil {
	// TODO: Handle error
}
```

## Development

1. Install [Go 1.11+](https://golang.org/)
2. `go mod vendor`
3. `go test`

#### For other language implementations visit:

[WebPush Libs](https://github.com/web-push-libs)
