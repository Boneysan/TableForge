# Secure Google Cloud Storage Upload Pipeline

## Overview

This document outlines the comprehensive secure asset upload pipeline implemented for Google Cloud Storage (GCS) with enterprise-grade security features including content validation, metadata sanitization, and signed URLs.

## Security Features

### ✅ Content-Type Validation
- **Allowed MIME Types**: Images (JPEG, PNG, GIF, WebP, SVG, BMP, TIFF), Documents (PDF, TXT, MD, JSON), Audio (MP3, WAV, OGG, M4A, WebM)
- **Extension Allowlist**: Enforced mapping between content types and file extensions
- **Header Validation**: Validates file signatures (magic numbers) for images
- **Content-Type Enforcement**: Server-side verification that content type matches file extension

### 🔒 File Size Limits
- **Images**: 50MB maximum
- **Documents**: 100MB maximum
- **Audio**: 200MB maximum  
- **Default**: 25MB for other file types

### 🧹 Metadata Sanitization
- **EXIF Stripping**: Automatically removes metadata from images using Sharp library
- **Filename Sanitization**: Removes dangerous characters, prevents directory traversal
- **Timestamp Prefixing**: Adds unique timestamps and hashes to prevent collisions
- **Content Validation**: Validates file headers and checks for null bytes in text files

### 🔐 Signed URLs & Access Control
- **Server-Side URL Generation**: All upload URLs generated server-side with 15-minute TTL
- **Authenticated Endpoints**: All upload operations require Firebase authentication
- **Rate Limiting**: Asset upload endpoints have dedicated rate limits
- **Security Headers**: Custom headers for upload tracking and validation

## API Endpoints

### POST `/api/objects/upload`
Generates secure upload URL with comprehensive validation.

**Request Body:**
```json
{
  "filename": "example.jpg",
  "contentType": "image/jpeg", 
  "fileSize": 1024000,
  "category": "private" // or "public"
}
```

**Response:**
```json
{
  "success": true,
  "upload": {
    "uploadUrl": "https://storage.googleapis.com/...",
    "fields": {
      "Content-Type": "image/jpeg",
      "x-upload-id": "uuid-here",
      "x-original-filename": "example.jpg",
      "x-sanitized-filename": "1754887000000_abc123de_example.jpg",
      "x-file-category": "image"
    },
    "metadata": {
      "originalName": "example.jpg",
      "sanitizedName": "1754887000000_abc123de_example.jpg", 
      "contentType": "image/jpeg",
      "category": "image",
      "uploadId": "uuid-here"
    }
  },
  "security": {
    "validation": "passed",
    "sanitized": true,
    "contentTypeEnforced": true,
    "sizeLimitEnforced": true
  }
}
```

### POST `/api/objects/process` 
Processes uploaded file with sanitization and validation.

**Request Body:**
```json
{
  "uploadId": "uuid-here",
  "objectPath": "/objects/path/to/file",
  "contentType": "image/jpeg"
}
```

**Response:**
```json
{
  "success": true,
  "processing": {
    "completed": true,
    "sanitized": true,
    "processedSize": 856000,
    "originalSize": 1024000
  },
  "metadata": {
    "contentType": "image/jpeg",
    "size": 856000,
    "uploadedAt": "2025-08-11T04:43:59.897Z",
    "isProcessed": true
  }
}
```

## Security Validation Process

1. **Request Validation**
   - Validates filename, content-type, and file size
   - Sanitizes filename and removes dangerous characters
   - Checks extension against allowlist

2. **Content-Type Verification** 
   - Validates MIME type against approved list
   - Ensures content-type matches file extension
   - Validates file headers/signatures

3. **Size Limit Enforcement**
   - Category-specific size limits enforced
   - Prevents large file uploads that could impact performance

4. **Secure URL Generation**
   - Server-side signed URL generation with TTL
   - Unique upload paths with timestamp and hash prefixes
   - Category-based storage location (public/private)

5. **Post-Upload Processing**
   - Downloads and validates file content
   - Strips EXIF metadata from images using Sharp
   - Re-uploads sanitized version if modified
   - Sets processing metadata flags

## File Storage Structure

```
/replit-objstore-{bucket-id}/
├── public/
│   └── uploads/
│       ├── image/
│       ├── document/
│       └── audio/
└── .private/
    └── uploads/
        ├── image/
        ├── document/
        └── audio/
```

## Rate Limiting

- **Asset Upload Endpoints**: Dedicated `assetUploadRateLimit` applied
- **Per-IP Limits**: Prevents abuse from single sources
- **Per-User Limits**: Authenticated user rate limiting
- **Bypass for Health Checks**: `/health` and `/api/health` endpoints excluded

## Middleware Stack

1. **assetUploadRateLimit**: Rate limiting for upload endpoints
2. **hybridAuthMiddleware**: Firebase/Replit authentication
3. **validateUploadMiddleware**: Upload request validation
4. **uploadSecurityHeaders**: Security headers for uploads

## Error Handling

All validation failures return structured error responses:

```json
{
  "success": false,
  "error": "Detailed error message",
  "code": "ERROR_CODE"
}
```

**Common Error Codes:**
- `UPLOAD_VALIDATION_FAILED`: Request validation failed
- `PROCESSING_FAILED`: Post-upload processing failed  
- `PROCESSING_ERROR`: Server error during processing

## Configuration

### Environment Variables
- `PUBLIC_OBJECT_SEARCH_PATHS`: Comma-separated public storage paths
- `PRIVATE_OBJECT_DIR`: Private storage directory path

### Dependencies
- **sharp**: Image processing and metadata stripping
- **@google-cloud/storage**: Google Cloud Storage client
- **express-rate-limit**: Rate limiting middleware

## Security Best Practices

1. **Fail-Closed Validation**: All validation failures result in request rejection
2. **Content-Type Enforcement**: Server validates that uploaded content matches declared type
3. **Filename Sanitization**: All filenames sanitized to prevent attacks
4. **Metadata Stripping**: EXIF and other metadata automatically removed from images
5. **Size Limits**: Enforced at multiple levels to prevent resource exhaustion
6. **Authentication Required**: All upload operations require valid authentication
7. **Rate Limiting**: Prevents abuse with tiered rate limits
8. **Signed URLs**: Short-lived signed URLs prevent unauthorized access

## Integration Example

```javascript
// Client-side upload flow
const uploadFile = async (file) => {
  // 1. Get secure upload URL
  const uploadResponse = await fetch('/api/objects/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      filename: file.name,
      contentType: file.type,
      fileSize: file.size,
      category: 'private'
    })
  });
  
  const { upload } = await uploadResponse.json();
  
  // 2. Upload file to signed URL
  await fetch(upload.uploadUrl, {
    method: 'PUT',
    headers: {
      'Content-Type': upload.fields['Content-Type']
    },
    body: file
  });
  
  // 3. Process uploaded file
  const processResponse = await fetch('/api/objects/process', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      uploadId: upload.metadata.uploadId,
      objectPath: `/objects/${upload.metadata.uploadId}_${upload.metadata.sanitizedName}`,
      contentType: upload.metadata.contentType
    })
  });
  
  return await processResponse.json();
};
```

This secure upload pipeline provides enterprise-grade security while maintaining performance and usability for asset uploads in the Vorpal Board platform.