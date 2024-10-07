package webpush_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hcarriz/webpush-go/v2"
)

type testHTTPClient struct{}

func (*testHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 201}, nil
}

func getURLEncodedTestSubscription() webpush.Subscription {

	return webpush.Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: webpush.Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ",
		},
	}
}

func getStandardEncodedTestSubscription() webpush.Subscription {
	return webpush.Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: webpush.Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ==",
		},
	}
}

func TestOptions_Send(t *testing.T) {

	opts := []webpush.Option{
		webpush.SetClient(&testHTTPClient{}),
		webpush.SetTopic("test_topic"),
		webpush.SetTTL(0),
		webpush.SetUrgency(webpush.UrgencyLow),
	}

	type args struct {
		subscriber   string
		public       string
		private      string
		subscription webpush.Subscription
		message      []byte
		opts         []webpush.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "defaults",
			args: args{
				subscriber:   "noreply@example.com",
				public:       "public",
				private:      "private",
				subscription: getStandardEncodedTestSubscription(),
				message:      []byte("test"),
				opts:         []webpush.Option{webpush.SetClient(&testHTTPClient{})},
			},
			wantErr: false,
		},
		{
			name: "standard encoding test",
			args: args{
				subscriber:   "noreply@example.com",
				public:       "public",
				private:      "private",
				subscription: getStandardEncodedTestSubscription(),
				message:      []byte("test"),
				opts:         opts,
			},
			wantErr: false,
		},
		{
			name: "url encoding test",
			args: args{
				subscriber:   "noreply@example.com",
				public:       "public",
				private:      "private",
				subscription: getURLEncodedTestSubscription(),
				message:      []byte("test"),
				opts:         opts,
			},
			wantErr: false,
		},
		{
			name: "send too large notification",
			args: args{
				subscriber:   "noreply@example.com",
				public:       "public",
				private:      "private",
				subscription: getStandardEncodedTestSubscription(),
				message:      []byte(strings.Repeat("test", int(webpush.MaxRecordSize))),
				opts:         opts,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := webpush.New(tt.args.subscriber, tt.args.private, tt.args.public, tt.args.opts...)
			if err != nil {
				t.Fatalf("unable to create new webpush client, got error = %v", err)
			}

			resp, err := o.Send(tt.args.subscription, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Options.Send() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if resp == nil {
					t.Fatalf("response is nil")
				}
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("received http status code %d instead of %d", resp.StatusCode, http.StatusCreated)
				}
			}

		})
	}
}

func TestClient_SkipForEndpoint(t *testing.T) {

	type args struct {
		endpoint string
		exclude  []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "don't exclude microsoft",
			args: args{
				endpoint: "https://wns2-by3p.notify.windows.com/w/?token=BQYAA",
			},
			want: false,
		},
		{
			name: "exclude microsoft",
			args: args{
				endpoint: "https://wns2-by3p.notify.windows.com/w/?token=BQYAA",
				exclude:  []string{"windows.com"},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := webpush.New("test@test.com", "test", "test", webpush.SetTTL(0, tt.args.exclude...))
			if err != nil {
				t.Fatal(err)
			}

			if got := c.SkipForEndpoint(tt.args.endpoint); got != tt.want {
				t.Errorf("Client.SkipForEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
