# Research Paper 46: SSRF via User Avatar Remote URL Import

## Summary
When platforms allow users to specify an image URL for avatar import, the backend image download engine (e.g. Sharp, ImageMagick, libcurl) makes an HTTP request without validating the resolved IP address. Supplying AWS/GCP metadata endpoints (`http://169.254.169.254/computeMetadata/v1/`) leaks cloud IAM instance tokens in the rendered image or error response.

## Tactical Patterns
- Target Technology: Sharp, ImageMagick, AWS EC2, GCP Compute
- Endpoint Pattern: `/api/v1/user/avatar/url`
- Endpoint Pattern: `/api/v1/media/import`
- Endpoint Pattern: `/api/v1/preview/thumbnail`
- Category: SSRF, Cloud Security
