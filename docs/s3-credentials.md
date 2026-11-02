# S3 credentials

S3 requests are signed by default. With neither `storage.s3_access_key` nor
`storage.s3_secret_key` configured, NORA uses the credential providers in
`object_store`: AWS environment keys (including `AWS_SESSION_TOKEN`), EKS IRSA,
ECS task credentials, EKS Pod Identity, then EC2 instance-profile credentials.
Temporary credentials are refreshed by the provider.

For EKS IRSA, annotate the pod's service account with its IAM role ARN. The EKS
webhook supplies `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`; NORA reads
these settings and exchanges the projected token with STS. Do not configure
static S3 keys. The role needs access to the configured bucket, and the pod
needs network access to regional STS and S3.

```toml
[storage]
mode = "s3"
s3_url = "https://s3.us-east-1.amazonaws.com"
bucket = "my-registry"
s3_region = "us-east-1"
```

`NORA_STORAGE_*` environment variables still override these TOML settings.
An explicit access/secret key pair takes precedence over ambient credentials;
an incomplete pair is a configuration error. A session token from the ambient
environment is not attached to an explicit NORA key pair.

Only credential-related `AWS_*` settings are imported. Configure the endpoint,
region, addressing style and anonymous access through NORA's own settings;
`AWS_ENDPOINT_URL_S3` and `AWS_SKIP_SIGNATURE` do not override them. Shared AWS
profile files and arbitrary assume-role profiles are not loaded.

## Anonymous buckets and emulators

Previously, omitting static keys silently selected unsigned requests. Deployments
that intentionally used that behavior must now set:

```toml
[storage]
s3_anonymous = true
```

Or set `NORA_STORAGE_S3_ANONYMOUS=true`. This disables signing and ignores ambient
credentials. It cannot be combined with explicit NORA S3 keys. Values other than
`true`, `false`, `1`, or `0` are rejected for the environment setting.

This setting controls access to object storage, independently of anonymous
package downloads (`auth.anonymous_read`).
