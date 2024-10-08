package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	MaxRecordSize   uint32 = 4096
	DefaultDuration        = time.Second * 30
	DefaultTimeout         = time.Second * 30
	DefaultTTL             = time.Second * 30
)

var (
	ErrMaxPadExceeded = errors.New("payload has exceeded the maximum length")
	ErrNilClient      = errors.New("client is nil")
	ErrEmptyParameter = errors.New("parameter is empty")
	ErrInvalidUrgency = errors.New("urgency is invalid")

	ErrNilSubscriptionEndpoint   = errors.New("subscription endpoint is nil")
	ErrMissingSubscriptionAuth   = errors.New("subscription is missing auth key")
	ErrMissingSubscriptionP256DH = errors.New("subscription is missing p256dh key")
	ErrInvalidSubscriber         = errors.New("subscriber is neither a valid email or a https link")
)

// saltFunc generates a salt of 16 bytes
func saltFunc() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return salt, err
	}

	return salt, nil
}

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client configuration that's needed to send a notification.
type Client struct {
	client             HTTPClient
	recordSize         uint32
	subscriber         string
	topic              string
	ttl                time.Duration
	urgency            Urgency
	expirationDuration time.Duration
	privateKey         string
	publicKey          string
	excludeZeroTTL     []string
}

// Check if the client will skip the endpoint.
//
// Example: if you use SetTTL(0, "windows.com"), it will return true for "https://wns2-by3p.notify.windows.com/....".
func (c Client) SkipForEndpoint(endpoint string) bool {

	if c.ttl > 0 || len(c.excludeZeroTTL) == 0 {
		return false
	}

	ep, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	for _, end := range c.excludeZeroTTL {

		if strings.HasSuffix(ep.Host, end) {
			return true
		}

	}

	return false

}

// Option configures the client.
type Option interface {
	apply(*Client) error
}

type option func(*Client) error

func (o option) apply(c *Client) error {
	return o(c)
}

type MissingParameter string

func (mp MissingParameter) Error() string {

	r := string(mp)

	if r == "" {
		return ""
	}

	return fmt.Sprintf("%s is missing", r)

}

// Clients sets the client to be used for the request.
//
// client can not be nil
func SetClient(client HTTPClient) Option {
	return option(func(o *Client) error {

		if client == nil {
			return ErrNilClient
		}

		o.client = client

		return nil
	})
}

// SetRecordSize is used to limit the record size.
func SetRecordSize(size uint32) Option {
	return option(func(o *Client) error {
		o.recordSize = size
		return nil
	})
}

// SetTopic can set the SetTopic header to collapse a pending messages
func SetTopic(topic string) Option {
	return option(func(o *Client) error {
		o.topic = topic
		return nil
	})
}

// Set the subscriber in the JWT token.
//
// sub can not be empty.
func SetSubscriber(sub string) Option {
	return option(func(o *Client) error {
		if sub == "" {
			return errors.Join(MissingParameter("sub from webpush.Subscriber"), ErrEmptyParameter)
		}
		return nil
	})
}

// Set the Urgency header to change a message priority
func SetUrgency(urgency Urgency) Option {
	return option(func(o *Client) error {

		if !ValidUrgency(urgency) {
			return ErrInvalidUrgency
		}

		o.urgency = urgency

		return nil
	})
}

// Set the TTL in seconds on the endpoint POST request.
//
// Certain browsers may have issues when TTL is set to 0. TTL must be >= 0 to be set.
//
// You can set the domains to exclude the zero ttl header with the exclude variable. This is not recommended.
func SetTTL(ttl int, exclude ...string) Option {
	return option(func(o *Client) error {
		if ttl >= 0 {
			o.ttl = time.Duration(ttl) * time.Second
		}
		if ttl == 0 {
			o.excludeZeroTTL = exclude
		}
		return nil
	})
}

// Set the TTL Duration on the endpoint POST request.
//
// Certain browsers may have issues when the TTL is set to 0.
func SetTTLDuration(ttl time.Duration) Option {
	return option(func(c *Client) error {
		c.ttl = ttl
		return nil
	})
}

// Set the expiration for VAPID JWT token
//
// Duration is capped to 24 hours. See https://www.rfc-editor.org/rfc/rfc8292#section-2
func SetExpirationDuration(d time.Duration) Option {
	return option(func(o *Client) error {

		if d >= 24*time.Hour {
			d = 24 * time.Hour
		}

		o.expirationDuration = d
		return nil
	})
}

// Set the private key to be used.
//
// Key can not be empty.
func SetPrivateKey(key string) Option {
	return option(func(o *Client) error {
		if key == "" {
			return errors.Join(MissingParameter("key in webpush.SetPrivateKey"), ErrEmptyParameter)
		}
		o.privateKey = key
		return nil
	})
}

// Set the public key to be used.
//
// Key can not be empty.
func SetPublicKey(key string) Option {
	return option(func(o *Client) error {
		if key == "" {
			return errors.Join(MissingParameter("key in webpush.SetPublicKey"), ErrEmptyParameter)
		}
		o.publicKey = key
		return nil
	})
}

func New(sub, private, public string, opts ...Option) (*Client, error) {

	var err error

	sub, err = formatVAPIDJWTSubject(sub)
	if err != nil {
		return nil, err
	}

	o := &Client{
		client:             &http.Client{Timeout: DefaultTimeout},
		subscriber:         sub,
		privateKey:         private,
		publicKey:          public,
		recordSize:         MaxRecordSize,
		expirationDuration: DefaultDuration,
		ttl:                DefaultTTL,
	}

	if err := o.Set(opts...); err != nil {
		return nil, err
	}

	return o, nil
}

func (o *Client) Set(opts ...Option) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt.apply(o); err != nil {
			return err
		}

	}

	if o.subscriber == "" {
		return errors.Join(MissingParameter("subscriber"), ErrEmptyParameter)
	}

	if o.privateKey == "" {
		return errors.Join(MissingParameter("private key"), ErrEmptyParameter)
	}

	if o.publicKey == "" {
		return errors.Join(MissingParameter("public key"), ErrEmptyParameter)
	}

	return nil
}

// Send calls SendWithContext with default context for backwards-compatibility
func (o *Client) Send(subscription Subscription, message []byte) (*http.Response, error) {
	return o.SendWithContext(context.Background(), subscription, message)
}

// SendWithContext sends a push notification to a subscription's endpoint
// Message Encryption for Web Push, and VAPID protocols.
// FOR MORE INFORMATION SEE RFC8291: https://datatracker.ietf.org/doc/rfc8291
func (o *Client) SendWithContext(ctx context.Context, s Subscription, message []byte, overrides ...Option) (*http.Response, error) {

	if err := s.Validate(); err != nil {
		return nil, err
	}

	// Copy the options
	options := &Client{
		client:             o.client,
		recordSize:         o.recordSize,
		subscriber:         o.subscriber,
		topic:              o.topic,
		ttl:                o.ttl,
		urgency:            o.urgency,
		expirationDuration: o.expirationDuration,
		privateKey:         o.privateKey,
		publicKey:          o.publicKey,
		excludeZeroTTL:     o.excludeZeroTTL,
	}

	if err := options.Set(overrides...); err != nil {
		return nil, err
	}

	// Authentication secret (auth_secret)
	authSecret, err := decodeSubscriptionKey(s.Keys.Auth)
	if err != nil {
		return nil, err
	}

	// dh (Diffie Hellman)
	dh, err := decodeSubscriptionKey(s.Keys.P256dh)
	if err != nil {
		return nil, err
	}

	// Generate 16 byte salt
	salt, err := saltFunc()
	if err != nil {
		return nil, err
	}

	// Create the ecdh_secret shared key pair
	curve := ecdh.P256()

	// Application server key pairs (single use)
	pk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	localPublicKey := pk.PublicKey().Bytes()

	// Combine application keys with receiver's EC public key
	sharedX, err := curve.NewPublicKey(dh)
	if err != nil {
		return nil, err
	}

	sharedECDHSecret, err := pk.ECDH(sharedX)
	if err != nil {
		return nil, err
	}

	hash := sha256.New

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(dh)
	prkInfoBuf.Write(localPublicKey)

	prkHKDF := hkdf.New(hash, sharedECDHSecret, authSecret, prkInfoBuf.Bytes())
	ikm, err := getHKDFKey(prkHKDF, 32)
	if err != nil {
		return nil, err
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := []byte("Content-Encoding: aes128gcm\x00")
	contentHKDF := hkdf.New(hash, ikm, salt, contentEncryptionKeyInfo)
	contentEncryptionKey, err := getHKDFKey(contentHKDF, 16)
	if err != nil {
		return nil, err
	}

	// Derive the Nonce
	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonceHKDF := hkdf.New(hash, ikm, salt, nonceInfo)
	nonce, err := getHKDFKey(nonceHKDF, 12)
	if err != nil {
		return nil, err
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Get the record size
	recordSize := options.recordSize

	recordLength := int(recordSize) - 16

	// Encryption Content-Coding Header
	recordBuf := bytes.NewBuffer(salt)

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, recordSize)

	recordBuf.Write(rs)
	recordBuf.Write([]byte{byte(len(localPublicKey))})
	recordBuf.Write(localPublicKey)

	// Data
	dataBuf := bytes.NewBuffer(message)

	// Pad content to max record size - 16 - header
	// Padding ending delimeter
	dataBuf.Write([]byte("\x02"))
	if err := pad(dataBuf, recordLength-recordBuf.Len()); err != nil {
		return nil, err
	}

	// Compose the ciphertext
	ciphertext := gcm.Seal([]byte{}, nonce, dataBuf.Bytes(), nil)
	recordBuf.Write(ciphertext)

	// POST request
	req, err := http.NewRequestWithContext(ctx, "POST", s.Endpoint, recordBuf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Length", strconv.Itoa(int(recordSize)))
	req.Header.Set("Content-Type", "application/octet-stream")

	// Not recommended
	if !options.SkipForEndpoint(s.Endpoint) {
		req.Header.Set("TTL", fmt.Sprintf("%.0f", options.ttl.Seconds()))
	}

	// Сheck the optional headers
	if len(options.topic) > 0 {
		req.Header.Set("Topic", options.topic)
	}

	if ValidUrgency(options.urgency) {
		req.Header.Set("Urgency", options.urgency.String())
	}

	expiration := time.Now().Add(options.expirationDuration)

	// Get VAPID Authorization header
	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		options.subscriber,
		options.publicKey,
		options.privateKey,
		expiration,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", vapidAuthHeader)

	return options.client.Do(req)
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

// Validate will check that everything is correct.
func (s Subscription) Validate() error {

	if s.Endpoint == "" {
		return ErrNilSubscriptionEndpoint
	}

	if s.Keys.Auth == "" {
		return ErrMissingSubscriptionAuth
	}

	if s.Keys.P256dh == "" {
		return ErrMissingSubscriptionP256DH
	}

	return nil
}

// decodeSubscriptionKey decodes a base64 subscription key.
// if necessary, add "=" padding to the key for URL decode
func decodeSubscriptionKey(key string) ([]byte, error) {
	// "=" padding
	buf := bytes.NewBufferString(key)
	if rem := len(key) % 4; rem != 0 {
		buf.WriteString(strings.Repeat("=", 4-rem))
	}

	bytes, err := base64.StdEncoding.DecodeString(buf.String())
	if err == nil {
		return bytes, nil
	}

	return base64.URLEncoding.DecodeString(buf.String())
}

// Returns a key of length "length" given an hkdf function
func getHKDFKey(hkdf io.Reader, length int) ([]byte, error) {
	key := make([]byte, length)
	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		return key, err
	}

	return key, nil
}

func pad(payload *bytes.Buffer, maxPadLen int) error {
	payloadLen := payload.Len()
	if payloadLen > maxPadLen {
		return ErrMaxPadExceeded
	}

	padLen := maxPadLen - payloadLen

	padding := make([]byte, padLen)
	payload.Write(padding)

	return nil
}
