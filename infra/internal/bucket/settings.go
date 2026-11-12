package bucket

import "fmt"

type Settings struct {
	Endpoint       string `name:"s3-endpoint" env:"TUNNELD_S3_ENDPOINT" required:"" help:"S3 endpoint URL (tunneld's setting)."`
	Region         string `name:"s3-region" env:"TUNNELD_S3_REGION" default:"us-east-1" help:"S3 region (tunneld's setting)."`
	Bucket         string `name:"s3-bucket" env:"TUNNELD_S3_BUCKET" required:"" help:"S3 bucket (tunneld's setting)."`
	AccessKey      string `name:"s3-access-key" env:"TUNNELD_S3_ACCESS_KEY" required:"" help:"S3 access key (secret, tunneld's setting)."`
	SecretKey      string `name:"s3-secret-key" env:"TUNNELD_S3_SECRET_KEY" required:"" help:"S3 secret key (secret, tunneld's setting)."`
	ForcePathStyle bool   `name:"s3-force-path-style" env:"TUNNELD_S3_FORCE_PATH_STYLE" default:"true" negatable:"" help:"Path-style addressing (tunneld's setting)."`
}

func (s Settings) Config() (Config, error) {
	for _, v := range []struct{ setting, value string }{
		{"--s3-endpoint (TUNNELD_S3_ENDPOINT)", s.Endpoint},
		{"--s3-bucket (TUNNELD_S3_BUCKET)", s.Bucket},
		{"--s3-access-key (TUNNELD_S3_ACCESS_KEY)", s.AccessKey},
		{"--s3-secret-key (TUNNELD_S3_SECRET_KEY)", s.SecretKey},
	} {
		if v.value == "" {
			return Config{}, fmt.Errorf("the setting %s is empty", v.setting)
		}
	}
	return Config{
		Endpoint:       s.Endpoint,
		Region:         s.Region,
		Bucket:         s.Bucket,
		AccessKey:      s.AccessKey,
		SecretKey:      s.SecretKey,
		ForcePathStyle: s.ForcePathStyle,
	}, nil
}
