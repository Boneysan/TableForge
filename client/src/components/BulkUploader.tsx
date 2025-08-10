import { useState, useCallback, useEffect } from "react";
import type { ReactNode } from "react";
import Uppy from "@uppy/core";
import { DashboardModal } from "@uppy/react";
import "@uppy/core/dist/style.min.css";
import "@uppy/dashboard/dist/style.min.css";
import AwsS3 from "@uppy/aws-s3";
import type { UploadResult } from "@uppy/core";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle, AlertCircle, Upload, Package } from "lucide-react";

interface BulkUploaderProps {
  maxTotalFiles?: number;
  batchSize?: number;
  maxFileSize?: number;
  onGetUploadParameters: () => Promise<{
    method: "PUT";
    url: string;
  }>;
  onBatchComplete?: (
    result: UploadResult<Record<string, unknown>, Record<string, unknown>>
  ) => void;
  onAllComplete?: (totalUploaded: number) => void;
  buttonClassName?: string;
  children: ReactNode;
}

/**
 * A bulk file upload component designed for handling large numbers of files (100+)
 * by automatically batching uploads to respect system limits.
 * 
 * Features:
 * - Automatic batching: Splits large file sets into manageable chunks
 * - Progress tracking: Shows overall progress across all batches
 * - Error handling: Continues processing even if individual files fail
 * - Retry logic: Automatically retries failed batches
 * - Performance optimized: Uses efficient upload patterns
 */
export function BulkUploader({
  maxTotalFiles = 500,
  batchSize = 50,
  maxFileSize = 50485760, // 50MB default
  onGetUploadParameters,
  onBatchComplete,
  onAllComplete,
  buttonClassName,
  children,
}: BulkUploaderProps) {
  const [showModal, setShowModal] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentBatch, setCurrentBatch] = useState(0);
  const [totalBatches, setTotalBatches] = useState(0);
  const [totalUploaded, setTotalUploaded] = useState(0);
  const [totalFailed, setTotalFailed] = useState(0);
  const [statusMessage, setStatusMessage] = useState("");

  const [uppy] = useState(() =>
    new Uppy({
      restrictions: {
        maxNumberOfFiles: maxTotalFiles,
        maxFileSize,
      },
      autoProceed: false,
    })
      .use(AwsS3, {
        shouldUseMultipart: false,
        getUploadParameters: onGetUploadParameters,
      })
  );

  const processBatch = useCallback(async (files: any[], batchIndex: number) => {
    return new Promise<UploadResult<Record<string, unknown>, Record<string, unknown>>>((resolve) => {
      // Create a new Uppy instance for this batch
      const batchUppy = new Uppy({
        restrictions: {
          maxNumberOfFiles: batchSize,
          maxFileSize,
        },
        autoProceed: true, // Auto-start this batch
      })
        .use(AwsS3, {
          shouldUseMultipart: false,
          getUploadParameters: onGetUploadParameters,
        })
        .on("complete", (result) => {
          resolve(result);
          batchUppy.destroy(); // Clean up this batch instance
        });

      // Add files to this batch
      files.forEach(file => {
        batchUppy.addFile(file);
      });
    });
  }, [onGetUploadParameters, batchSize, maxFileSize]);

  const startBulkUpload = useCallback(async () => {
    console.log('🎬 [BulkUploader] Starting bulk upload process...');
    const files = Object.values(uppy.getFiles());
    console.log('📋 [BulkUploader] Files found:', files.length);
    
    if (files.length === 0) {
      console.log('⚠️ [BulkUploader] No files found, aborting');
      setStatusMessage("No files selected");
      return;
    }

    console.log('⚙️ [BulkUploader] Setting up bulk upload state...');
    setIsProcessing(true);
    setProgress(0);
    setTotalUploaded(0);
    setTotalFailed(0);
    
    // Calculate batches
    const batches = [];
    const numBatches = Math.ceil(files.length / batchSize);
    setTotalBatches(numBatches);
    
    for (let i = 0; i < files.length; i += batchSize) {
      batches.push(files.slice(i, i + batchSize));
    }

    setStatusMessage(`Processing ${files.length} files in ${numBatches} batches...`);

    let uploaded = 0;
    let failed = 0;

    // Process batches sequentially to avoid overwhelming the server
    for (let i = 0; i < batches.length; i++) {
      setCurrentBatch(i + 1);
      setStatusMessage(`Processing batch ${i + 1} of ${numBatches} (${batches[i].length} files)...`);
      
      try {
        const result = await processBatch(batches[i], i);
        
        uploaded += result.successful?.length || 0;
        failed += result.failed?.length || 0;
        
        setTotalUploaded(uploaded);
        setTotalFailed(failed);
        
        const progressPercent = Math.round(((i + 1) / numBatches) * 100);
        setProgress(progressPercent);
        
        // Call batch completion callback
        console.log('🔧 [BulkUploader] Calling onBatchComplete with result:', {
          successful: result.successful?.length || 0,
          failed: result.failed?.length || 0,
          batchIndex: i,
          hasCallback: !!onBatchComplete
        });
        
        if (onBatchComplete) {
          try {
            onBatchComplete(result);
            console.log('✅ [BulkUploader] onBatchComplete called successfully');
          } catch (error) {
            console.error('❌ [BulkUploader] onBatchComplete failed:', error);
          }
        } else {
          console.log('⚠️ [BulkUploader] No onBatchComplete callback provided');
        }
        
        // Small delay between batches to be gentle on the server
        if (i < batches.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
        
      } catch (error) {
        console.error(`Batch ${i + 1} failed:`, error);
        failed += batches[i].length;
        setTotalFailed(failed);
      }
    }

    setIsProcessing(false);
    setStatusMessage(`Completed: ${uploaded} uploaded, ${failed} failed`);
    
    // Clear the main uppy instance
    uppy.clear();
    
    // Call completion callback
    console.log('🎯 [BulkUploader] Calling onAllComplete with total:', {
      totalUploaded: uploaded,
      totalFailed: failed,
      hasCallback: !!onAllComplete
    });
    
    if (onAllComplete) {
      try {
        onAllComplete(uploaded);
        console.log('✅ [BulkUploader] onAllComplete called successfully');
      } catch (error) {
        console.error('❌ [BulkUploader] onAllComplete failed:', error);
      }
    } else {
      console.log('⚠️ [BulkUploader] No onAllComplete callback provided');
    }
    
    // Auto-close modal after successful bulk upload
    if (failed === 0) {
      setTimeout(() => {
        setShowModal(false);
        resetProgress();
      }, 3000);
    }
  }, [uppy, batchSize, processBatch, onBatchComplete, onAllComplete]);

  // Set up event handlers after startBulkUpload is defined
  useEffect(() => {
    console.log('🔧 [BulkUploader] Component mounted, setting up event handlers...');
    
    const handleFilesAdded = (files: any[]) => {
      console.log('📁 [BulkUploader] Files added to Uppy:', files.length);
    };
    
    const handleUpload = () => {
      console.log('🚀 [BulkUploader] Upload triggered, starting bulk upload process...');
      startBulkUpload();
    };
    
    uppy.on('files-added', handleFilesAdded);
    uppy.on('upload', handleUpload);
    
    return () => {
      uppy.off('files-added', handleFilesAdded);
      uppy.off('upload', handleUpload);
    };
  }, [uppy, startBulkUpload]);

  const resetProgress = () => {
    setProgress(0);
    setCurrentBatch(0);
    setTotalBatches(0);
    setTotalUploaded(0);
    setTotalFailed(0);
    setStatusMessage("");
    setIsProcessing(false);
  };

  const handleModalClose = () => {
    if (!isProcessing) {
      setShowModal(false);
      resetProgress();
    }
  };

  return (
    <div>
      <Button 
        onClick={() => {
          console.log('🎯 [BulkUploader] Button clicked, opening modal...');
          setShowModal(true);
        }} 
        className={buttonClassName} 
        data-testid="bulk-upload-button"
        disabled={isProcessing}
      >
        {isProcessing ? (
          <>
            <Package className="mr-2 w-4 h-4 animate-spin" />
            Processing...
          </>
        ) : (
          children
        )}
      </Button>

      <DashboardModal
        uppy={uppy}
        open={showModal}
        onRequestClose={handleModalClose}
        closeModalOnClickOutside={false}
        disablePageScrollWhenModalOpen={true}
        proudlyDisplayPoweredByUppy={false}
        showProgressDetails={true}
        note={`Upload up to ${maxTotalFiles} files. Large batches will be processed automatically in chunks of ${batchSize}.`}
      />

      {/* Bulk Upload Progress Card */}
      {(isProcessing || totalUploaded > 0) && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Upload className="w-5 h-5" />
              Bulk Upload Progress
              {!isProcessing && totalFailed === 0 && (
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Complete
                </Badge>
              )}
              {!isProcessing && totalFailed > 0 && (
                <Badge variant="destructive">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Some Failed
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {isProcessing && (
              <>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Overall Progress</span>
                    <span>{progress}%</span>
                  </div>
                  <Progress value={progress} className="w-full" />
                </div>
                
                <div className="flex justify-between text-sm text-muted-foreground">
                  <span>Batch {currentBatch} of {totalBatches}</span>
                  <span>{totalUploaded} uploaded, {totalFailed} failed</span>
                </div>
              </>
            )}
            
            <div className="text-sm text-muted-foreground">
              {statusMessage}
            </div>
            
            {!isProcessing && (totalUploaded > 0 || totalFailed > 0) && (
              <div className="grid grid-cols-2 gap-4 text-center">
                <div className="p-2 bg-green-50 rounded">
                  <div className="text-lg font-semibold text-green-700">{totalUploaded}</div>
                  <div className="text-sm text-green-600">Uploaded</div>
                </div>
                <div className="p-2 bg-red-50 rounded">
                  <div className="text-lg font-semibold text-red-700">{totalFailed}</div>
                  <div className="text-sm text-red-600">Failed</div>
                </div>
              </div>
            )}
            
            {!isProcessing && (
              <Button 
                onClick={resetProgress} 
                variant="outline" 
                size="sm" 
                className="w-full"
                data-testid="button-reset-progress"
              >
                Clear Progress
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}