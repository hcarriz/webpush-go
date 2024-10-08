package webpush

import "testing"

func Test_formatSubscriber(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{
			name:    "blank",
			arg:     "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "unencrypted http check",
			arg:     "http://example.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "https check",
			arg:     "https://example.com",
			want:    "https://example.com",
			wantErr: false,
		},
		{
			name:    "sftp check",
			arg:     "sftp://example.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "random text",
			arg:     "randomtext",
			want:    "",
			wantErr: true,
		},
		{
			name:    "email",
			arg:     "john@doe.com",
			want:    "mailto:john@doe.com",
			wantErr: false,
		},
		{
			name:    "email - 2",
			arg:     "mailto:john@doe.com",
			want:    "mailto:john@doe.com",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatVAPIDJWTSubject(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("formatSubscriber() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("formatSubscriber() = %v, want %v", got, tt.want)
			}
		})
	}
}
