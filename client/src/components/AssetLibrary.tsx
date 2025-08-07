import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Folder, Upload, ChevronDown, ChevronUp, Layers, Coins, Map } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ObjectUploader } from "@/components/ObjectUploader";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useDragAndDrop } from "@/hooks/useDragAndDrop";
import type { GameAsset } from "@shared/schema";
import type { UploadResult } from "@uppy/core";

interface AssetLibraryProps {
  roomId: string;
  assets: GameAsset[];
  onAssetUploaded: () => void;
}

export function AssetLibrary({ roomId, assets, onAssetUploaded }: AssetLibraryProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['cards', 'tokens', 'map'])
  );
  const { toast } = useToast();
  const { dragStart } = useDragAndDrop();

  const createAssetMutation = useMutation({
    mutationFn: async (data: {
      roomId: string;
      name: string;
      type: string;
      filePath: string;
      width?: number;
      height?: number;
      uploadedBy: string;
    }) => {
      const response = await apiRequest("POST", "/api/assets", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rooms", roomId, "assets"] });
      onAssetUploaded();
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to save asset. Please try again.",
        variant: "destructive",
      });
    },
  });

  const getUploadParameters = async () => {
    const response = await apiRequest("POST", "/api/objects/upload", {});
    const data = await response.json();
    return {
      method: "PUT" as const,
      url: data.uploadURL,
    };
  };

  const handleUploadComplete = (result: UploadResult<Record<string, unknown>, Record<string, unknown>>) => {
    if (result.successful && result.successful.length > 0) {
      const file = result.successful[0];
      const fileName = file.name || "Untitled Asset";
      const fileType = fileName.toLowerCase().includes('card') ? 'card' :
                      fileName.toLowerCase().includes('token') ? 'token' :
                      fileName.toLowerCase().includes('map') ? 'map' : 'other';

      createAssetMutation.mutate({
        roomId,
        name: fileName,
        type: fileType,
        filePath: file.uploadURL || "",
        uploadedBy: "mock-user-id", // In a real app, get from auth
      });
    }
  };

  const toggleCategory = (category: string) => {
    const newExpanded = new Set(expandedCategories);
    if (newExpanded.has(category)) {
      newExpanded.delete(category);
    } else {
      newExpanded.add(category);
    }
    setExpandedCategories(newExpanded);
  };

  const categorizedAssets = {
    cards: assets.filter(asset => asset.type === 'card'),
    tokens: assets.filter(asset => asset.type === 'token'),
    map: assets.filter(asset => asset.type === 'map'),
    other: assets.filter(asset => asset.type === 'other'),
  };

  const categoryIcons = {
    cards: Layers,
    tokens: Coins,
    map: Map,
    other: Folder,
  };

  const categoryColors = {
    cards: "text-[#7C3AED]",
    tokens: "text-[#F59E0B]",
    map: "text-[#10B981]",
    other: "text-gray-400",
  };

  const handleAssetDragStart = (asset: GameAsset, event: React.DragEvent) => {
    dragStart(event, {
      type: 'asset',
      data: asset,
    });
  };

  return (
    <aside className="w-80 bg-[#374151] border-r border-gray-600 flex flex-col" data-testid="asset-library">
      <div className="p-4 border-b border-gray-600">
        <h2 className="text-lg font-semibold mb-3 flex items-center">
          <Folder className="mr-2 text-[#10B981]" />
          Game Assets
        </h2>
        
        <ObjectUploader
          maxNumberOfFiles={10}
          maxFileSize={10485760}
          onGetUploadParameters={getUploadParameters}
          onComplete={handleUploadComplete}
          buttonClassName="w-full bg-[#2563EB] hover:bg-blue-700 text-white py-2 px-4 rounded-lg transition-colors flex items-center justify-center"
        >
          <Upload className="mr-2 w-4 h-4" />
          Upload Assets
        </ObjectUploader>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4">
        {Object.entries(categorizedAssets).map(([category, categoryAssets]) => {
          const Icon = categoryIcons[category as keyof typeof categoryIcons];
          const iconColor = categoryColors[category as keyof typeof categoryColors];
          const isExpanded = expandedCategories.has(category);
          
          return (
            <div key={category} className="mb-6">
              <button 
                className="flex items-center justify-between w-full text-left mb-2 text-gray-300 hover:text-white transition-colors"
                onClick={() => toggleCategory(category)}
                data-testid={`button-toggle-${category}`}
              >
                <span className="font-medium flex items-center capitalize">
                  <Icon className={`mr-2 w-4 h-4 ${iconColor}`} />
                  {category}
                </span>
                {isExpanded ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>
              
              {isExpanded && (
                <div className="space-y-2 ml-6">
                  {categoryAssets.length === 0 ? (
                    <div className="text-sm text-gray-500 italic">
                      No {category} uploaded yet
                    </div>
                  ) : (
                    categoryAssets.map((asset) => (
                      <div
                        key={asset.id}
                        className="flex items-center p-2 bg-[#4B5563] rounded-lg hover:bg-gray-500 cursor-grab active:cursor-grabbing transition-colors"
                        draggable
                        onDragStart={(e) => handleAssetDragStart(asset, e)}
                        data-testid={`asset-${asset.id}`}
                      >
                        <img 
                          src={asset.filePath.startsWith('/objects/') 
                            ? asset.filePath 
                            : `/public-objects/${asset.filePath}`
                          } 
                          alt={asset.name}
                          className="w-8 h-8 rounded object-cover mr-2"
                          onError={(e) => {
                            const target = e.target as HTMLImageElement;
                            target.src = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHZpZXdCb3g9IjAgMCAzMiAzMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiBmaWxsPSIjNEI1NTYzIi8+CjxwYXRoIGQ9Ik0xNiA5QzEyLjEzNCA5IDkgMTIuMTM0IDkgMTZTMTIuMTM0IDIzIDE2IDIzUzIzIDE5Ljg2NiAyMyAxNlMxOS44NjYgOSAxNiA5Wk0xNiAyMUMxMy4yMzkgMjEgMTEgMTguNzYxIDExIDE2UzEzLjIzOSAxMSAxNiAxMVMxOSAxMy4yMzkgMTkgMTZTMTguNzYxIDIxIDE2IDIxWiIgZmlsbD0iIzZCNzI4MCIvPgo8L3N2Zz4K";
                          }}
                        />
                        <div className="flex-1">
                          <div className="text-sm font-medium text-gray-100" data-testid={`text-asset-name-${asset.id}`}>
                            {asset.name}
                          </div>
                          <div className="text-xs text-gray-400">
                            {asset.type}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
