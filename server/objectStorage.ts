import { Storage, File } from "@google-cloud/storage";
import { Response } from "express";
import { randomUUID } from "crypto";
import { 
  validateUploadRequest,
  sanitizeImageMetadata,
  validateFileContent,
  type SecureUploadParams
} from './middleware/uploadSecurity';
import {
  ObjectAclPolicy,
  ObjectPermission,
  canAccessObject,
  getObjectAclPolicy,
  setObjectAclPolicy,
} from "./objectAcl";

const REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";

// The object storage client is used to interact with the object storage service.
export const objectStorageClient = new Storage({
  credentials: {
    audience: "replit",
    subject_token_type: "access_token",
    token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
    type: "external_account",
    credential_source: {
      url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
      format: {
        type: "json",
        subject_token_field_name: "access_token",
      },
    },
    universe_domain: "googleapis.com",
  },
  projectId: "",
});

export class ObjectNotFoundError extends Error {
  constructor() {
    super("Object not found");
    this.name = "ObjectNotFoundError";
    Object.setPrototypeOf(this, ObjectNotFoundError.prototype);
  }
}

// The object storage service is used to interact with the object storage service.
export class ObjectStorageService {
  constructor() {}

  // Gets the storage client instance
  getStorageClient() {
    return objectStorageClient;
  }

  // Gets the public object search paths.
  getPublicObjectSearchPaths(): Array<string> {
    const pathsStr = process.env.PUBLIC_OBJECT_SEARCH_PATHS || "";
    const paths = Array.from(
      new Set(
        pathsStr
          .split(",")
          .map((path) => path.trim())
          .filter((path) => path.length > 0)
      )
    );
    if (paths.length === 0) {
      throw new Error(
        "PUBLIC_OBJECT_SEARCH_PATHS not set. Create a bucket in 'Object Storage' " +
          "tool and set PUBLIC_OBJECT_SEARCH_PATHS env var (comma-separated paths)."
      );
    }
    return paths;
  }

  // Gets the private object directory.
  getPrivateObjectDir(): string {
    const dir = process.env.PRIVATE_OBJECT_DIR || "";
    if (!dir) {
      throw new Error(
        "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' " +
          "tool and set PRIVATE_OBJECT_DIR env var."
      );
    }
    return dir;
  }

  // Search for a public object from the search paths.
  async searchPublicObject(filePath: string): Promise<File | null> {
    for (const searchPath of this.getPublicObjectSearchPaths()) {
      const fullPath = `${searchPath}/${filePath}`;

      // Full path format: /<bucket_name>/<object_name>
      const { bucketName, objectName } = parseObjectPath(fullPath);
      const bucket = objectStorageClient.bucket(bucketName);
      const file = bucket.file(objectName);

      // Check if file exists
      const [exists] = await file.exists();
      if (exists) {
        return file;
      }
    }

    return null;
  }

  // Downloads an object to the response.
  async downloadObject(file: File, res: Response, cacheTtlSec: number = 3600) {
    try {
      // Get file metadata
      const [metadata] = await file.getMetadata();
      // Get the ACL policy for the object.
      const aclPolicy = await getObjectAclPolicy(file);
      const isPublic = aclPolicy?.visibility === "public";
      // Set appropriate headers
      res.set({
        "Content-Type": metadata.contentType || "application/octet-stream",
        "Content-Length": metadata.size,
        "Cache-Control": `${
          isPublic ? "public" : "private"
        }, max-age=${cacheTtlSec}`,
      });

      // Stream the file to the response
      const stream = file.createReadStream();

      stream.on("error", (err) => {
        console.error("Stream error:", err);
        if (!res.headersSent) {
          res.status(500).json({ error: "Error streaming file" });
        }
      });

      stream.pipe(res);
    } catch (error) {
      console.error("Error downloading file:", error);
      if (!res.headersSent) {
        res.status(500).json({ error: "Error downloading file" });
      }
    }
  }

  // Gets the secure upload URL for an object entity with validation
  async getSecureUploadURL(
    filename: string,
    contentType: string,
    fileSize: number,
    category?: 'public' | 'private'
  ): Promise<SecureUploadParams> {
    console.log(`🔒 [Object Storage] Requesting secure upload for: ${filename}, type: ${contentType}, size: ${fileSize}`);
    
    // Validate upload request first
    const validation = validateUploadRequest(filename, contentType, fileSize);
    if (!validation.isValid) {
      throw new Error(`Upload validation failed: ${validation.error}`);
    }
    
    const uploadId = randomUUID();
    
    // Determine storage location based on category
    const objectDir = category === 'public' 
      ? this.getPublicObjectSearchPaths()[0] // Use first public path
      : this.getPrivateObjectDir();
    
    if (!objectDir) {
      throw new Error("Object storage directory not configured");
    }
    
    // Create secure path with validation data
    const securePath = `${objectDir}/uploads/${validation.category}/${uploadId}_${validation.sanitizedFilename}`;
    
    const { bucketName, objectName } = parseObjectPath(securePath);
    
    console.log(`🔒 [Object Storage] Generated secure path: ${securePath}`);
    console.log(`🔒 [Object Storage] Bucket: ${bucketName}, Object: ${objectName}`);
    
    // Generate signed URL with security constraints
    const uploadUrl = await signObjectURL({
      bucketName,
      objectName,
      method: "PUT",
      ttlSec: 900 // 15 minutes
    });
    
    const uploadParams: SecureUploadParams = {
      uploadUrl,
      fields: {
        'Content-Type': validation.contentType!,
        'x-upload-id': uploadId,
        'x-original-filename': filename,
        'x-sanitized-filename': validation.sanitizedFilename!,
        'x-file-category': validation.category!
      },
      metadata: {
        originalName: filename,
        sanitizedName: validation.sanitizedFilename!,
        contentType: validation.contentType!,
        category: validation.category!,
        uploadId
      }
    };
    
    console.log(`✅ [Object Storage] Secure upload URL generated for ${validation.sanitizedFilename}`);
    return uploadParams;
  }
  
  // Legacy method for backwards compatibility
  async getObjectEntityUploadURL(): Promise<string> {
    const result = await this.getSecureUploadURL('temp.jpg', 'image/jpeg', 1024, 'private');
    return result.uploadUrl;
  }

  // Gets the object entity file from the object path.
  async getObjectEntityFile(objectPath: string): Promise<File> {
    if (!objectPath.startsWith("/objects/")) {
      throw new ObjectNotFoundError();
    }

    const parts = objectPath.slice(1).split("/");
    if (parts.length < 2) {
      throw new ObjectNotFoundError();
    }

    const entityId = parts.slice(1).join("/");
    let entityDir = this.getPrivateObjectDir();
    if (!entityDir.endsWith("/")) {
      entityDir = `${entityDir}/`;
    }
    const objectEntityPath = `${entityDir}${entityId}`;
    const { bucketName, objectName } = parseObjectPath(objectEntityPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const objectFile = bucket.file(objectName);
    const [exists] = await objectFile.exists();
    if (!exists) {
      throw new ObjectNotFoundError();
    }
    return objectFile;
  }

  normalizeObjectEntityPath(
    rawPath: string,
  ): string {
    if (!rawPath.startsWith("https://storage.googleapis.com/")) {
      return rawPath;
    }
  
    // Extract the path from the URL by removing query parameters and domain
    const url = new URL(rawPath);
    const rawObjectPath = url.pathname;
  
    let objectEntityDir = this.getPrivateObjectDir();
    if (!objectEntityDir.endsWith("/")) {
      objectEntityDir = `${objectEntityDir}/`;
    }
  
    if (!rawObjectPath.startsWith(objectEntityDir)) {
      return rawObjectPath;
    }
  
    // Extract the entity ID from the path
    const entityId = rawObjectPath.slice(objectEntityDir.length);
    return `/objects/${entityId}`;
  }

  // Tries to set the ACL policy for the object entity and return the normalized path.
  async trySetObjectEntityAclPolicy(
    rawPath: string,
    aclPolicy: ObjectAclPolicy
  ): Promise<string> {
    const normalizedPath = this.normalizeObjectEntityPath(rawPath);
    if (!normalizedPath.startsWith("/")) {
      return normalizedPath;
    }

    const objectFile = await this.getObjectEntityFile(normalizedPath);
    await setObjectAclPolicy(objectFile, aclPolicy);
    return normalizedPath;
  }

  // Checks if the user can access the object entity.
  async canAccessObjectEntity({
    userId,
    objectFile,
    requestedPermission,
  }: {
    userId?: string;
    objectFile: File;
    requestedPermission?: ObjectPermission;
  }): Promise<boolean> {
    return canAccessObject({
      userId,
      objectFile,
      requestedPermission: requestedPermission ?? ObjectPermission.READ,
    });
  }
  
  // Process and sanitize uploaded file
  async processUploadedFile(
    file: File,
    originalContentType: string
  ): Promise<{ success: boolean; error?: string; processedSize?: number }> {
    console.log(`🔄 [Object Storage] Processing uploaded file: ${file.name}`);
    
    try {
      // Download the file content
      const [buffer] = await file.download();
      console.log(`📥 [Object Storage] Downloaded file content: ${buffer.length} bytes`);
      
      // Validate file content
      const contentValidation = await validateFileContent(buffer, originalContentType);
      if (!contentValidation.isValid) {
        console.error(`❌ [Object Storage] Content validation failed: ${contentValidation.error}`);
        return { success: false, error: contentValidation.error };
      }
      
      // Sanitize metadata for images
      let processedBuffer = buffer;
      if (originalContentType.startsWith('image/')) {
        processedBuffer = await sanitizeImageMetadata(buffer, originalContentType);
        console.log(`🧹 [Object Storage] Image metadata sanitized: ${buffer.length} → ${processedBuffer.length} bytes`);
      }
      
      // Re-upload the processed file if it was modified
      if (processedBuffer !== buffer) {
        await file.save(processedBuffer, {
          metadata: {
            contentType: originalContentType,
            metadata: {
              'processed': 'true',
              'sanitized': 'true',
              'processed-at': new Date().toISOString()
            }
          }
        });
        console.log(`✅ [Object Storage] File re-uploaded after processing`);
      }
      
      return { 
        success: true, 
        processedSize: processedBuffer.length 
      };
      
    } catch (error) {
      console.error('❌ [Object Storage] Error processing uploaded file:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown processing error' 
      };
    }
  }
  
  // Get file metadata with security validation
  async getSecureFileMetadata(file: File): Promise<{
    size: number;
    contentType: string;
    isProcessed: boolean;
    uploadedAt?: Date;
    sanitized?: boolean;
  }> {
    const [metadata] = await file.getMetadata();
    
    return {
      size: Number(metadata.size) || 0,
      contentType: metadata.contentType || 'application/octet-stream',
      isProcessed: metadata.metadata?.processed === 'true',
      sanitized: metadata.metadata?.sanitized === 'true',
      uploadedAt: metadata.timeCreated ? new Date(metadata.timeCreated) : undefined
    };
  }

  // Lists all files in the uploads directory
  async listUploadedFiles(): Promise<Array<{ name: string; size: number; timeCreated: string; path: string }>> {
    const privateObjectDir = this.getPrivateObjectDir();
    const uploadsPath = `${privateObjectDir}/uploads/`;
    const { bucketName, objectName } = parseObjectPath(uploadsPath);
    
    const bucket = objectStorageClient.bucket(bucketName);
    const [files] = await bucket.getFiles({
      prefix: objectName,
    });

    return files.map(file => ({
      name: file.name,
      size: file.metadata.size ? parseInt(file.metadata.size) : 0,
      timeCreated: file.metadata.timeCreated || '',
      path: `/${bucketName}/${file.name}`
    }));
  }

  // Deletes a file from Google Cloud Storage
  async deleteFile(filePath: string): Promise<boolean> {
    try {
      const { bucketName, objectName } = parseObjectPath(filePath);
      const bucket = objectStorageClient.bucket(bucketName);
      const file = bucket.file(objectName);
      
      const [exists] = await file.exists();
      if (!exists) {
        return false;
      }
      
      await file.delete();
      console.log(`🗑️ [Storage] Deleted file: ${filePath}`);
      return true;
    } catch (error) {
      console.error(`❌ [Storage] Failed to delete file ${filePath}:`, error);
      return false;
    }
  }

  // Finds and deletes orphaned files (files in storage without database records)
  async cleanupOrphanedFiles(): Promise<{ deleted: number; errors: number; fileList: string[] }> {
    const files = await this.listUploadedFiles();
    const deletedFiles: string[] = [];
    let deleted = 0;
    let errors = 0;

    console.log(`🧹 [Storage Cleanup] Found ${files.length} files in uploads directory`);

    for (const file of files) {
      try {
        // Extract the file path from the full object path
        const filePath = file.path.split('/').slice(2).join('/'); // Remove bucket name from path
        
        // Check if this file is referenced in any game asset
        const storage = await import('./storage');
        const referencedAsset = await storage.storage.findAssetByFilePath(`/objects/uploads/${filePath.split('/').pop()}`);
        
        if (!referencedAsset) {
          console.log(`🗑️ [Storage Cleanup] Deleting orphaned file: ${file.name}`);
          const success = await this.deleteFile(file.path);
          if (success) {
            deleted++;
            deletedFiles.push(file.name);
          } else {
            errors++;
          }
        } else {
          console.log(`✅ [Storage Cleanup] File has database record: ${file.name}`);
        }
      } catch (error) {
        console.error(`❌ [Storage Cleanup] Error processing file ${file.name}:`, error);
        errors++;
      }
    }

    console.log(`🧹 [Storage Cleanup] Complete: ${deleted} deleted, ${errors} errors`);
    return { deleted, errors, fileList: deletedFiles };
  }
}

function parseObjectPath(path: string): {
  bucketName: string;
  objectName: string;
} {
  if (!path.startsWith("/")) {
    path = `/${path}`;
  }
  const pathParts = path.split("/");
  if (pathParts.length < 3) {
    throw new Error("Invalid path: must contain at least a bucket name");
  }

  const bucketName = pathParts[1];
  const objectName = pathParts.slice(2).join("/");

  return {
    bucketName,
    objectName,
  };
}

async function signObjectURL({
  bucketName,
  objectName,
  method,
  ttlSec,
}: {
  bucketName: string;
  objectName: string;
  method: "GET" | "PUT" | "DELETE" | "HEAD";
  ttlSec: number;
}): Promise<string> {
  const request = {
    bucket_name: bucketName,
    object_name: objectName,
    method,
    expires_at: new Date(Date.now() + ttlSec * 1000).toISOString(),
  };
  const response = await fetch(
    `${REPLIT_SIDECAR_ENDPOINT}/object-storage/signed-object-url`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    throw new Error(
      `Failed to sign object URL, errorcode: ${response.status}, ` +
        `make sure you're running on Replit`
    );
  }

  const { signed_url: signedURL } = await response.json();
  return signedURL;
}
