import { Request, Response, NextFunction } from 'express';
import { File } from '@google-cloud/storage';
import sharp from 'sharp';
import { createHash } from 'crypto';

// Allowed file types and extensions
export const ALLOWED_MIME_TYPES = {
  images: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
    'image/bmp',
    'image/tiff'
  ],
  documents: [
    'application/pdf',
    'text/plain',
    'text/markdown',
    'application/json'
  ],
  audio: [
    'audio/mpeg',
    'audio/wav',
    'audio/ogg',
    'audio/mp4',
    'audio/webm'
  ]
};

export const ALLOWED_EXTENSIONS = {
  images: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp', '.tiff'],
  documents: ['.pdf', '.txt', '.md', '.json'],
  audio: ['.mp3', '.wav', '.ogg', '.m4a', '.webm']
};

// File size limits (in bytes)
export const SIZE_LIMITS = {
  image: 50 * 1024 * 1024, // 50MB for images
  document: 100 * 1024 * 1024, // 100MB for documents
  audio: 200 * 1024 * 1024, // 200MB for audio
  default: 25 * 1024 * 1024 // 25MB default
};

// Security validation for upload requests
export interface UploadValidationResult {
  isValid: boolean;
  error?: string;
  sanitizedFilename?: string;
  contentType?: string;
  category?: 'image' | 'document' | 'audio';
}

/**
 * Validate file upload request for security
 */
export function validateUploadRequest(
  filename: string,
  contentType: string,
  fileSize: number,
  category?: string
): UploadValidationResult {
  console.log(`🔍 [Upload Security] Validating upload: ${filename}, type: ${contentType}, size: ${fileSize}`);

  // Sanitize filename
  const sanitizedFilename = sanitizeFilename(filename);
  if (!sanitizedFilename) {
    return { isValid: false, error: 'Invalid filename' };
  }

  // Validate file extension
  const extension = getFileExtension(sanitizedFilename);
  if (!isAllowedExtension(extension)) {
    return { 
      isValid: false, 
      error: `File extension ${extension} not allowed. Allowed extensions: ${Object.values(ALLOWED_EXTENSIONS).flat().join(', ')}` 
    };
  }

  // Validate content type
  if (!isAllowedContentType(contentType)) {
    return { 
      isValid: false, 
      error: `Content type ${contentType} not allowed. Allowed types: ${Object.values(ALLOWED_MIME_TYPES).flat().join(', ')}` 
    };
  }

  // Determine file category
  const fileCategory = determineFileCategory(contentType, extension);
  
  // Validate file size
  const sizeLimit = getSizeLimit(fileCategory);
  if (fileSize > sizeLimit) {
    return { 
      isValid: false, 
      error: `File size ${formatFileSize(fileSize)} exceeds limit of ${formatFileSize(sizeLimit)} for ${fileCategory} files` 
    };
  }

  // Validate content type matches extension
  if (!isContentTypeMatchingExtension(contentType, extension)) {
    return { 
      isValid: false, 
      error: `Content type ${contentType} does not match file extension ${extension}` 
    };
  }

  return {
    isValid: true,
    sanitizedFilename,
    contentType,
    category: fileCategory
  };
}

/**
 * Sanitize filename for security
 */
function sanitizeFilename(filename: string): string | null {
  if (!filename || filename.length === 0) return null;
  
  // Remove or replace dangerous characters
  let sanitized = filename
    .replace(/[^a-zA-Z0-9\-_\.\s]/g, '') // Remove special chars except dash, underscore, dot, space
    .replace(/\s+/g, '_') // Replace spaces with underscores
    .replace(/_{2,}/g, '_') // Replace multiple underscores with single
    .replace(/^[._]+|[._]+$/g, '') // Remove leading/trailing dots and underscores
    .toLowerCase();
  
  // Ensure filename is not empty and has reasonable length
  if (sanitized.length === 0 || sanitized.length > 255) return null;
  
  // Ensure it has an extension
  if (!sanitized.includes('.')) return null;
  
  // Prevent directory traversal
  if (sanitized.includes('..') || sanitized.includes('/') || sanitized.includes('\\')) {
    return null;
  }
  
  // Add timestamp prefix to avoid collisions
  const timestamp = Date.now();
  const hash = createHash('md5').update(filename).digest('hex').substring(0, 8);
  
  return `${timestamp}_${hash}_${sanitized}`;
}

/**
 * Get file extension from filename
 */
function getFileExtension(filename: string): string {
  const lastDot = filename.lastIndexOf('.');
  return lastDot === -1 ? '' : filename.substring(lastDot).toLowerCase();
}

/**
 * Check if file extension is allowed
 */
function isAllowedExtension(extension: string): boolean {
  const allExtensions = Object.values(ALLOWED_EXTENSIONS).flat();
  return allExtensions.includes(extension);
}

/**
 * Check if content type is allowed
 */
function isAllowedContentType(contentType: string): boolean {
  const allTypes = Object.values(ALLOWED_MIME_TYPES).flat();
  return allTypes.includes(contentType);
}

/**
 * Determine file category from content type and extension
 */
function determineFileCategory(contentType: string, extension: string): 'image' | 'document' | 'audio' {
  if (ALLOWED_MIME_TYPES.images.includes(contentType) || ALLOWED_EXTENSIONS.images.includes(extension)) {
    return 'image';
  }
  if (ALLOWED_MIME_TYPES.documents.includes(contentType) || ALLOWED_EXTENSIONS.documents.includes(extension)) {
    return 'document';
  }
  if (ALLOWED_MIME_TYPES.audio.includes(contentType) || ALLOWED_EXTENSIONS.audio.includes(extension)) {
    return 'audio';
  }
  return 'document'; // Default fallback
}

/**
 * Get size limit for file category
 */
function getSizeLimit(category: 'image' | 'document' | 'audio'): number {
  return SIZE_LIMITS[category] || SIZE_LIMITS.default;
}

/**
 * Format file size for human reading
 */
function formatFileSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;
  
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  
  return `${size.toFixed(1)}${units[unitIndex]}`;
}

/**
 * Check if content type matches file extension
 */
function isContentTypeMatchingExtension(contentType: string, extension: string): boolean {
  const mappings: Record<string, string[]> = {
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/webp': ['.webp'],
    'image/svg+xml': ['.svg'],
    'image/bmp': ['.bmp'],
    'image/tiff': ['.tiff'],
    'application/pdf': ['.pdf'],
    'text/plain': ['.txt'],
    'text/markdown': ['.md'],
    'application/json': ['.json'],
    'audio/mpeg': ['.mp3'],
    'audio/wav': ['.wav'],
    'audio/ogg': ['.ogg'],
    'audio/mp4': ['.m4a'],
    'audio/webm': ['.webm']
  };
  
  const allowedExtensions = mappings[contentType];
  return allowedExtensions ? allowedExtensions.includes(extension) : false;
}

/**
 * Sanitize image metadata (remove EXIF data)
 */
export async function sanitizeImageMetadata(buffer: Buffer, contentType: string): Promise<Buffer> {
  console.log(`🧹 [Metadata Sanitizer] Processing ${contentType} image, size: ${buffer.length} bytes`);
  
  try {
    if (!contentType.startsWith('image/')) {
      return buffer; // Not an image, return as-is
    }
    
    // Skip SVG files as they don't have EXIF data
    if (contentType === 'image/svg+xml') {
      return buffer;
    }
    
    // Use Sharp to strip metadata and re-encode
    const sanitized = await sharp(buffer)
      .withMetadata(false) // Remove all metadata including EXIF
      .jpeg({ quality: 90, progressive: true }) // Convert to JPEG with good quality
      .toBuffer();
    
    console.log(`✅ [Metadata Sanitizer] Sanitized image: ${buffer.length} → ${sanitized.length} bytes`);
    return sanitized;
    
  } catch (error) {
    console.error('❌ [Metadata Sanitizer] Error sanitizing image:', error);
    // Return original buffer if sanitization fails
    return buffer;
  }
}

/**
 * Validate uploaded file content
 */
export async function validateFileContent(buffer: Buffer, contentType: string): Promise<{ isValid: boolean; error?: string }> {
  console.log(`🔍 [Content Validator] Validating ${contentType} file content, size: ${buffer.length} bytes`);
  
  try {
    // Check for null bytes (potential binary injection)
    if (buffer.includes(0x00) && !contentType.startsWith('image/') && !contentType.startsWith('audio/')) {
      return { isValid: false, error: 'File contains null bytes' };
    }
    
    // For images, validate file headers
    if (contentType.startsWith('image/')) {
      const isValidImage = await validateImageHeader(buffer, contentType);
      if (!isValidImage) {
        return { isValid: false, error: 'Invalid image file header' };
      }
    }
    
    // For text files, check encoding
    if (contentType.startsWith('text/')) {
      try {
        buffer.toString('utf8');
      } catch (error) {
        return { isValid: false, error: 'Invalid text encoding' };
      }
    }
    
    return { isValid: true };
    
  } catch (error) {
    console.error('❌ [Content Validator] Error validating file content:', error);
    return { isValid: false, error: 'Failed to validate file content' };
  }
}

/**
 * Validate image file headers
 */
async function validateImageHeader(buffer: Buffer, contentType: string): Promise<boolean> {
  try {
    // Check file signatures (magic numbers)
    const signatures: Record<string, number[]> = {
      'image/jpeg': [0xFF, 0xD8, 0xFF],
      'image/png': [0x89, 0x50, 0x4E, 0x47],
      'image/gif': [0x47, 0x49, 0x46],
      'image/webp': [0x52, 0x49, 0x46, 0x46],
      'image/bmp': [0x42, 0x4D]
    };
    
    const expectedSig = signatures[contentType];
    if (!expectedSig) {
      return true; // No signature check for this type
    }
    
    // Check if buffer starts with expected signature
    for (let i = 0; i < expectedSig.length; i++) {
      if (buffer[i] !== expectedSig[i]) {
        return false;
      }
    }
    
    // Additional validation using Sharp
    if (contentType !== 'image/svg+xml') {
      await sharp(buffer).metadata();
    }
    
    return true;
    
  } catch (error) {
    console.error('❌ [Image Validator] Error validating image header:', error);
    return false;
  }
}

/**
 * Generate secure upload parameters
 */
export interface SecureUploadParams {
  uploadUrl: string;
  fields: Record<string, string>;
  metadata: {
    originalName: string;
    sanitizedName: string;
    contentType: string;
    category: string;
    uploadId: string;
  };
}

/**
 * Express middleware for upload validation
 */
export const validateUploadMiddleware = (req: Request, res: Response, next: NextFunction) => {
  console.log('🔍 [Upload Middleware] Validating upload request');
  
  const { filename, contentType, fileSize } = req.body;
  
  if (!filename || !contentType || !fileSize) {
    return res.status(400).json({
      error: 'validation_failed',
      message: 'Missing required fields: filename, contentType, fileSize'
    });
  }
  
  const validation = validateUploadRequest(filename, contentType, parseInt(fileSize));
  
  if (!validation.isValid) {
    console.warn(`❌ [Upload Middleware] Validation failed: ${validation.error}`);
    return res.status(400).json({
      error: 'validation_failed',
      message: validation.error
    });
  }
  
  // Attach validated data to request
  (req as any).uploadValidation = validation;
  
  console.log(`✅ [Upload Middleware] Upload validation passed for ${validation.sanitizedFilename}`);
  next();
};

/**
 * Security headers for file uploads
 */
export const uploadSecurityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Set security headers for upload endpoints
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.header('Content-Security-Policy', "default-src 'none'");
  
  next();
};