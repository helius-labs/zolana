package router

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSSource reads private, versioned S3 registry mirrors and the precise regional
// credential ARNs it names. The runtime role must have read-only access to those
// resources; routing publication and TUF signing use separate roles.
type AWSSource struct {
	config     aws.Config
	key, owner string
	locations  []registryLocation
}

// RegistryMirror holds an identical object key in another AWS region.
type RegistryMirror struct {
	Region string
	Bucket string
}

type registryLocation struct {
	RegistryMirror
	client *s3.Client
}

func NewAWSSource(config aws.Config, bucket, key, owner string, mirrors ...RegistryMirror) (*AWSSource, error) {
	if config.Region == "" || !accountID.MatchString(owner) || bucket == "" || strings.ContainsAny(bucket, "/:@\\ \t\r\n") || key == "" || strings.ContainsAny(key, "\r\n") {
		return nil, ErrRegistry
	}
	locations := append([]RegistryMirror{{Region: config.Region, Bucket: bucket}}, mirrors...)
	if len(locations) > 3 {
		return nil, ErrRegistry
	}
	source := &AWSSource{config: config, key: key, owner: owner}
	regions, buckets := map[string]bool{}, map[string]bool{}
	for _, location := range locations {
		if !identifier.MatchString(location.Region) || location.Bucket == "" || strings.ContainsAny(location.Bucket, "/:@\\ \t\r\n") || regions[location.Region] || buckets[location.Bucket] {
			return nil, ErrRegistry
		}
		regions[location.Region], buckets[location.Bucket] = true, true
		regional := config
		regional.Region = location.Region
		source.locations = append(source.locations, registryLocation{RegistryMirror: location, client: s3.NewFromConfig(regional)})
	}
	return source, nil
}

func (s *AWSSource) Registry(parent context.Context) (RegistryDocument, error) {
	type result struct {
		document RegistryDocument
		revision uint64
		index    int
	}
	results := make(chan result, len(s.locations))
	for index, location := range s.locations {
		go func() {
			ctx, cancel := context.WithTimeout(parent, 3*time.Second)
			defer cancel()
			value := result{index: index}
			document, err := s.readRegistry(ctx, location)
			if err == nil {
				if config, err := decodeRegistry(document.Data, time.Now()); err == nil {
					value.document, value.revision = document, config.Revision
				}
			}
			results <- value
		}()
	}
	var best result
	conflict := false
	for range s.locations {
		value := <-results
		if value.revision > best.revision {
			best, conflict = value, false
		} else if value.revision != 0 && value.revision == best.revision {
			if registryDigest(value.document.Data) != registryDigest(best.document.Data) {
				conflict = true
			}
			if value.index < best.index {
				best = value
			}
		}
	}
	if parent.Err() != nil || best.revision == 0 || conflict {
		return RegistryDocument{}, ErrRegistry
	}
	return best.document, nil
}

func (s *AWSSource) readRegistry(ctx context.Context, location registryLocation) (RegistryDocument, error) {
	response, err := location.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(location.Bucket), Key: aws.String(s.key), ExpectedBucketOwner: aws.String(s.owner)})
	if err != nil {
		return RegistryDocument{}, ErrRegistry
	}
	defer response.Body.Close()
	// Refuse an unversioned source: operators need recoverable publication history.
	if response.VersionId == nil || *response.VersionId == "" || *response.VersionId == "null" {
		return RegistryDocument{}, ErrRegistry
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRegistryBytes+1))
	if err != nil || len(data) > maxRegistryBytes {
		return RegistryDocument{}, ErrRegistry
	}
	return RegistryDocument{Data: data, Region: location.Region, Version: *response.VersionId}, nil
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
