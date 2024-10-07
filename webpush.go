package webpush

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/hcarriz/webpush-go/v2"
)

const MaxRecordSize = webpush.MaxRecordSize

var (
	ErrMaxPadExceeded  = webpush.ErrMaxPadExceeded
	ErrNilSubscription = errors.New("subscription is nil")
	ErrNilOptions      = errors.New("options is nil")
)

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	HTTPClient      HTTPClient // Will replace with *http.Client by default if not included
	RecordSize      uint32     // Limit the record size
	Subscriber      string     // Sub in VAPID JWT token
	Topic           string     // Set the Topic header to collapse a pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDPublicKey  string     // VAPID public key, passed in VAPID Authorization header
	VAPIDPrivateKey string     // VAPID private key, used to sign VAPID JWT token
	VapidExpiration time.Time  // optional expiration for VAPID JWT token (defaults to now + 12 hours)
}

// Keys are the base64 encoded values from PushSubscription.getKey()
type Keys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     Keys   `json:"keys"`
}

// SendNotification calls SendNotificationWithContext with default context for backwards-compatibility
func SendNotification(message []byte, s *Subscription, options *Options) (*http.Response, error) {
	return SendNotificationWithContext(context.Background(), message, s, options)
}

// SendNotificationWithContext sends a push notification to a subscription's endpoint
// Message Encryption for Web Push, and VAPID protocols.
// FOR MORE INFORMATION SEE RFC8291: https://datatracker.ietf.org/doc/rfc8291
func SendNotificationWithContext(ctx context.Context, message []byte, s *Subscription, options *Options) (*http.Response, error) {

	if s == nil {
		return nil, ErrNilSubscription
	}

	if options == nil {
		return nil, ErrNilOptions
	}

	opts := []webpush.Option{
		webpush.SetTopic(options.Topic),
		webpush.SetTTL(options.TTL),
	}

	if options.HTTPClient != nil {
		opts = append(opts, webpush.SetClient(options.HTTPClient))
	}

	if options.RecordSize > 0 {
		opts = append(opts, webpush.SetRecordSize(options.RecordSize))
	}

	if isValidUrgency(options.Urgency) {
		if urgency := webpush.Urgency(options.Urgency); webpush.ValidUrgency(urgency) {
			opts = append(opts, webpush.SetUrgency(urgency))
		}
	}

	if !options.VapidExpiration.IsZero() {
		opts = append(opts, webpush.SetExpirationDuration(time.Until(options.VapidExpiration)))
	}

	client, err := webpush.New(options.Subscriber, options.VAPIDPrivateKey, options.VAPIDPublicKey, opts...)
	if err != nil {
		return nil, err
	}

	sub := webpush.Subscription{
		Endpoint: s.Endpoint,
		Keys: webpush.Keys{
			Auth:   s.Keys.Auth,
			P256dh: s.Keys.P256dh,
		},
	}

	return client.SendWithContext(ctx, sub, message)

}
