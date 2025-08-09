import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { Save, FolderOpen, Download, Trash2, Eye, Users, Crown } from "lucide-react";
import type { GameTemplate } from "@shared/schema";

interface GameTemplateManagerProps {
  roomId: string;
  children: React.ReactNode;
}

export function GameTemplateManager({ roomId, children }: GameTemplateManagerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState("browse");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch templates
  const { data: templates = [], isLoading } = useQuery<GameTemplate[]>({
    queryKey: ['/api/templates'],
    enabled: isOpen,
  });

  // Save current room as template
  const saveTemplateMutation = useMutation({
    mutationFn: async (data: {
      name: string;
      description: string;
      isPublic: boolean;
      category: string;
      tags: string[];
    }) => {
      return apiRequest('POST', `/api/rooms/${roomId}/save-template`, data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Game template saved successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/templates'] });
      setActiveTab("browse");
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to save template",
        variant: "destructive",
      });
    },
  });

  // Apply template to room
  const applyTemplateMutation = useMutation({
    mutationFn: async (templateId: string) => {
      return apiRequest('POST', `/api/rooms/${roomId}/apply-template`, { templateId });
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Template applied to room successfully!",
      });
      setIsOpen(false);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to apply template",
        variant: "destructive",
      });
    },
  });

  // Delete template
  const deleteTemplateMutation = useMutation({
    mutationFn: async (templateId: string) => {
      return apiRequest('DELETE', `/api/templates/${templateId}`);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Template deleted successfully!",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/templates'] });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to delete template",
        variant: "destructive",
      });
    },
  });

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        {children}
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderOpen className="w-5 h-5" />
            Game Templates
          </DialogTitle>
        </DialogHeader>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="browse" className="flex items-center gap-2">
              <Eye className="w-4 h-4" />
              Browse Templates
            </TabsTrigger>
            <TabsTrigger value="save" className="flex items-center gap-2">
              <Save className="w-4 h-4" />
              Save Current Room
            </TabsTrigger>
          </TabsList>

          <TabsContent value="browse" className="mt-4">
            <ScrollArea className="h-[500px] pr-4">
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-muted-foreground">Loading templates...</div>
                </div>
              ) : templates.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-muted-foreground">No templates found</div>
                </div>
              ) : (
                <div className="grid gap-4">
                  {templates.map((template) => (
                    <TemplateCard
                      key={template.id}
                      template={template}
                      onApply={() => applyTemplateMutation.mutate(template.id)}
                      onDelete={() => deleteTemplateMutation.mutate(template.id)}
                      isApplying={applyTemplateMutation.isPending}
                      isDeleting={deleteTemplateMutation.isPending}
                    />
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="save" className="mt-4">
            <SaveTemplateForm
              onSave={(data) => saveTemplateMutation.mutate(data)}
              isSaving={saveTemplateMutation.isPending}
            />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

interface TemplateCardProps {
  template: GameTemplate;
  onApply: () => void;
  onDelete: () => void;
  isApplying: boolean;
  isDeleting: boolean;
}

function TemplateCard({ template, onApply, onDelete, isApplying, isDeleting }: TemplateCardProps) {
  return (
    <Card className="w-full" data-testid={`template-card-${template.id}`}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <CardTitle className="text-lg flex items-center gap-2">
              {template.name}
              {template.isPublic ? (
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Users className="w-3 h-3" />
                  Public
                </Badge>
              ) : (
                <Badge variant="outline" className="flex items-center gap-1">
                  <Crown className="w-3 h-3" />
                  Private
                </Badge>
              )}
            </CardTitle>
            <CardDescription className="mt-1">
              {template.description || "No description"}
            </CardDescription>
          </div>
        </div>
        
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          {template.category && (
            <span className="font-medium">{template.category}</span>
          )}
          {template.playersMin && template.playersMax && (
            <span>{template.playersMin}-{template.playersMax} players</span>
          )}
          {template.estimatedDuration && (
            <span>{template.estimatedDuration}</span>
          )}
        </div>

        {template.tags && template.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {template.tags.map((tag, index) => (
              <Badge key={index} variant="outline" className="text-xs">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </CardHeader>

      <CardContent className="pt-0">
        <div className="flex justify-between items-center">
          <div className="text-sm text-muted-foreground">
            Created {template.createdAt ? new Date(template.createdAt).toLocaleDateString() : 'Unknown date'}
          </div>
          <div className="flex gap-2">
            <Button 
              onClick={onApply}
              disabled={isApplying}
              size="sm"
              data-testid={`button-apply-template-${template.id}`}
            >
              <Download className="w-4 h-4 mr-1" />
              {isApplying ? "Applying..." : "Apply"}
            </Button>
            <Button 
              onClick={onDelete}
              disabled={isDeleting}
              size="sm"
              variant="outline"
              data-testid={`button-delete-template-${template.id}`}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface SaveTemplateFormProps {
  onSave: (data: {
    name: string;
    description: string;
    isPublic: boolean;
    category: string;
    tags: string[];
  }) => void;
  isSaving: boolean;
}

function SaveTemplateForm({ onSave, isSaving }: SaveTemplateFormProps) {
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    isPublic: false,
    category: "Custom",
    tags: [] as string[],
    tagInput: "",
  });

  const categories = [
    "Custom",
    "RPG",
    "Board Game",
    "Card Game",
    "Strategy",
    "Party Game",
    "War Game",
    "Abstract",
    "Simulation"
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) return;

    onSave({
      name: formData.name.trim(),
      description: formData.description.trim(),
      isPublic: formData.isPublic,
      category: formData.category,
      tags: formData.tags,
    });
  };

  const addTag = () => {
    const tag = formData.tagInput.trim();
    if (tag && !formData.tags.includes(tag)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, tag],
        tagInput: "",
      }));
    }
  };

  const removeTag = (tagToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove),
    }));
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4" data-testid="save-template-form">
      <div className="space-y-2">
        <Label htmlFor="template-name">Template Name</Label>
        <Input
          id="template-name"
          value={formData.name}
          onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
          placeholder="Enter template name..."
          required
          data-testid="input-template-name"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="template-description">Description</Label>
        <Textarea
          id="template-description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          placeholder="Describe your game template..."
          className="min-h-[80px]"
          data-testid="input-template-description"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="template-category">Category</Label>
          <Select 
            value={formData.category} 
            onValueChange={(value) => setFormData(prev => ({ ...prev, category: value }))}
          >
            <SelectTrigger data-testid="select-template-category">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {categories.map((category) => (
                <SelectItem key={category} value={category}>
                  {category}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label>Visibility</Label>
          <div className="flex items-center space-x-2 pt-2">
            <Checkbox
              id="template-public"
              checked={formData.isPublic}
              onCheckedChange={(checked) => 
                setFormData(prev => ({ ...prev, isPublic: !!checked }))
              }
              data-testid="checkbox-template-public"
            />
            <Label htmlFor="template-public" className="text-sm">
              Make this template public
            </Label>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <Label>Tags</Label>
        <div className="flex gap-2">
          <Input
            value={formData.tagInput}
            onChange={(e) => setFormData(prev => ({ ...prev, tagInput: e.target.value }))}
            placeholder="Add a tag..."
            onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
            data-testid="input-template-tag"
          />
          <Button type="button" onClick={addTag} variant="outline" size="sm">
            Add
          </Button>
        </div>
        
        {formData.tags.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {formData.tags.map((tag) => (
              <Badge key={tag} variant="secondary" className="flex items-center gap-1">
                {tag}
                <button
                  type="button"
                  onClick={() => removeTag(tag)}
                  className="ml-1 hover:text-red-500"
                >
                  ×
                </button>
              </Badge>
            ))}
          </div>
        )}
      </div>

      <Separator />

      <div className="flex justify-end gap-2">
        <Button 
          type="submit" 
          disabled={!formData.name.trim() || isSaving}
          data-testid="button-save-template"
        >
          <Save className="w-4 h-4 mr-2" />
          {isSaving ? "Saving..." : "Save Template"}
        </Button>
      </div>
    </form>
  );
}