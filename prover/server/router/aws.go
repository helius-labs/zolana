package router

import (
	"context"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSSource reads one private, versioned S3 registry and the precise regional
// credential ARNs it names. The runtime role must have read-only access to those
// resources; routing publication and TUF signing use separate roles.
type AWSSource struct {
	config             aws.Config
	bucket, key, owner string
	s3                 *s3.Client
}

func NewAWSSource(config aws.Config, bucket, key, owner string) (*AWSSource, error) {
	if config.Region == "" || !accountID.MatchString(owner) || bucket == "" || strings.ContainsAny(bucket, "/:@\\ \t\r\n") || key == "" || strings.ContainsAny(key, "\r\n") {
		return nil, ErrRegistry
	}
	return &AWSSource{config: config, bucket: bucket, key: key, owner: owner, s3: s3.NewFromConfig(config)}, nil
}

func (s *AWSSource) Registry(ctx context.Context) ([]byte, error) {
	response, err := s.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(s.key), ExpectedBucketOwner: aws.String(s.owner)})
	if err != nil {
		return nil, ErrRegistry
	}
	defer response.Body.Close()
	// Refuse an unversioned source: operators need recoverable publication history.
	if response.VersionId == nil || *response.VersionId == "" || *response.VersionId == "null" {
		return nil, ErrRegistry
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRegistryBytes+1))
	if err != nil || len(data) > maxRegistryBytes {
		return nil, ErrRegistry
	}
	return data, nil
}

func (s *AWSSource) Secret(ctx context.Context, arn string) (string, error) {
	match := secretARN.FindStringSubmatch(arn)
	if len(match) == 0 || match[3] != s.owner {
		return "", ErrRegistry
	}
	config := s.config
	config.Region = match[2]
	client := secretsmanager.NewFromConfig(config)
	response, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(arn)})
	if err != nil || response.SecretString == nil || !validAPIKey(*response.SecretString) {
		return "", ErrRegistry
	}
	return *response.SecretString, nil
}
