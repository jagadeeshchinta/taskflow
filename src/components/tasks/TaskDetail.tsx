"use client";

import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { GlassButton } from "@/components/ui/GlassButton";
import { PriorityBadge, StatusBadge } from "@/components/ui/GlassBadge";
import {
  X,
  Calendar,
  User,
  MessageSquare,
  Clock,
  Edit3,
  Trash2,
  MoreHorizontal,
  Paperclip,
  Download,
  FileText,
  Image as ImageIcon,
  Loader2,
  File,
} from "lucide-react";
import { GlassDropdown } from "@/components/ui/GlassDropdown";
import { toast } from "sonner";

interface AttachmentItem {
  id: string;
  filename: string;
  size: number;
  mimeType: string;
  createdAt: string;
}

interface TaskDetailProps {
  task: {
    id: string;
    title: string;
    description?: string;
    status: string;
    priority: string;
    tags: string[];
    assignee?: { name: string };
    dueDate?: string;
    createdAt?: string;
    attachments?: AttachmentItem[];
  };
  onClose: () => void;
  onAttachmentAdded?: (attachment: AttachmentItem) => void;
}

function formatBytes(bytes: number) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function getFileIcon(mimeType: string) {
  if (mimeType.startsWith("image/")) {
    return <ImageIcon className="w-4 h-4 text-emerald-400" />;
  }
  if (mimeType === "application/pdf") {
    return <FileText className="w-4 h-4 text-rose-400" />;
  }
  return <File className="w-4 h-4 text-sky-400" />;
}

export function TaskDetail({ task, onClose, onAttachmentAdded }: TaskDetailProps) {
  const [attachments, setAttachments] = useState<AttachmentItem[]>(task.attachments || []);
  const [isLoadingAttachments, setIsLoadingAttachments] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch latest attachments when task opens
  useEffect(() => {
    let isMounted = true;
    async function loadAttachments() {
      if (!task.id) return;
      try {
        setIsLoadingAttachments(true);
        const res = await fetch(`/api/tasks/${task.id}/attachments`);
        if (res.ok) {
          const data = await res.json();
          if (isMounted && data.attachments) {
            setAttachments(data.attachments);
          }
        }
      } catch (err) {
        console.error("Failed to load attachments:", err);
      } finally {
        if (isMounted) setIsLoadingAttachments(false);
      }
    }

    loadAttachments();
    return () => {
      isMounted = false;
    };
  }, [task.id]);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Reset input value so same file can be re-selected if needed
    e.target.value = "";

    // 1. Client-side MIME validation
    const allowedTypes = ["image/jpeg", "image/png", "image/webp", "application/pdf"];
    if (!allowedTypes.includes(file.type)) {
      toast.error("Invalid file type. Only JPEG, PNG, WebP, and PDF files are allowed.");
      return;
    }

    // 2. Reject dangerous file extensions
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext && ["svg", "exe", "bat", "cmd", "sh", "php", "js", "html"].includes(ext)) {
      toast.error("File type not permitted for security reasons.");
      return;
    }

    // 3. Client-side size check (5MB images, 10MB docs)
    const maxSizeBytes = file.type.startsWith("image/") ? 5 * 1024 * 1024 : 10 * 1024 * 1024;
    if (file.size > maxSizeBytes) {
      toast.error(
        `File exceeds maximum permitted size of ${file.type.startsWith("image/") ? "5 MB" : "10 MB"}.`
      );
      return;
    }

    try {
      setIsUploading(true);
      toast.info("Preparing secure S3 upload...");

      // Step A: Request presigned upload URL
      const presignRes = await fetch("/api/attachments/presign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          taskId: task.id,
          filename: file.name,
          fileType: file.type,
          fileSize: file.size,
        }),
      });

      const presignData = await presignRes.json();
      if (!presignRes.ok) {
        throw new Error(presignData.error || "Failed to obtain upload authorization");
      }

      // Step B: Upload file directly to S3 via presigned PUT URL
      toast.info("Uploading file to Amazon S3...");
      const s3UploadRes = await fetch(presignData.uploadUrl, {
        method: "PUT",
        headers: {
          "Content-Type": file.type,
        },
        body: file,
      });

      if (!s3UploadRes.ok) {
        throw new Error("Failed to upload file to Amazon S3 storage");
      }

      // Step C: Confirm attachment metadata in PostgreSQL via Prisma
      toast.info("Saving attachment metadata...");
      const confirmRes = await fetch("/api/attachments/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          taskId: task.id,
          filename: file.name,
          size: file.size,
          mimeType: file.type,
          key: presignData.key,
        }),
      });

      const confirmData = await confirmRes.json();
      if (!confirmRes.ok) {
        throw new Error(confirmData.error || "Failed to record attachment in database");
      }

      const newAttachment = confirmData.attachment;
      setAttachments((prev) => [newAttachment, ...prev]);
      onAttachmentAdded?.(newAttachment);
      toast.success("Attachment uploaded and verified successfully!");
    } catch (error: unknown) {
      console.error("[Attachment Upload Error]:", error);
      toast.error(error instanceof Error ? error.message : "Failed to upload attachment");
    } finally {
      setIsUploading(false);
    }
  };

  const handleDownload = async (attachment: AttachmentItem) => {
    try {
      setDownloadingId(attachment.id);
      const res = await fetch(`/api/attachments/${attachment.id}/download`);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to generate download URL");
      }

      // Direct download via presigned GET URL
      const link = document.createElement("a");
      link.href = data.downloadUrl;
      link.download = attachment.filename;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      toast.success(`Download started for ${attachment.filename}`);
    } catch (error: unknown) {
      console.error("[Download Error]:", error);
      toast.error(error instanceof Error ? error.message : "Failed to download attachment");
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 300 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 300 }}
      transition={{ type: "spring", damping: 25, stiffness: 300 }}
      className="fixed right-0 top-0 bottom-0 w-full max-w-lg z-50 border-l border-[hsl(var(--border))] overflow-y-auto"
      style={{ background: "hsl(var(--surface-elevated))" }}
    >
      {/* Header */}
      <div
        className="sticky top-0 flex items-center justify-between p-4 border-b border-[hsl(var(--border-subtle))] z-10"
        style={{ background: "hsl(var(--surface-elevated))" }}
      >
        <div className="flex items-center gap-2">
          <StatusBadge status={task.status} />
          <PriorityBadge priority={task.priority} />
        </div>
        <div className="flex items-center gap-1">
          <GlassDropdown
            align="right"
            trigger={
              <button className="p-2 rounded-lg hover:bg-glass-100 text-[hsl(var(--text-muted))]">
                <MoreHorizontal className="w-4 h-4" />
              </button>
            }
            items={[
              { id: "edit", label: "Edit", icon: <Edit3 className="w-4 h-4" />, onClick: () => {} },
              { id: "div", label: "", divider: true },
              { id: "delete", label: "Delete", icon: <Trash2 className="w-4 h-4" />, danger: true, onClick: () => {} },
            ]}
          />
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-glass-100 text-[hsl(var(--text-muted))] hover:text-[hsl(var(--text-primary))]"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      <div className="p-6 space-y-6">
        <h1 className="text-xl font-heading font-bold text-[hsl(var(--text-primary))]">{task.title}</h1>

        {task.description && (
          <p className="text-sm text-[hsl(var(--text-secondary))] leading-relaxed">{task.description}</p>
        )}

        {/* Meta Grid */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <p className="text-xs text-[hsl(var(--text-muted))] flex items-center gap-1.5">
              <User className="w-3 h-3" /> Assignee
            </p>
            <p className="text-sm text-[hsl(var(--text-primary))]">{task.assignee?.name || "Unassigned"}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-[hsl(var(--text-muted))] flex items-center gap-1.5">
              <Calendar className="w-3 h-3" /> Due Date
            </p>
            <p className="text-sm text-[hsl(var(--text-primary))]">{task.dueDate || "No due date"}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-[hsl(var(--text-muted))] flex items-center gap-1.5">
              <Clock className="w-3 h-3" /> Created
            </p>
            <p className="text-sm text-[hsl(var(--text-primary))]">{task.createdAt || "Just now"}</p>
          </div>
        </div>

        {/* Tags */}
        {task.tags.length > 0 && (
          <div>
            <p className="text-xs text-[hsl(var(--text-muted))] mb-2">Tags</p>
            <div className="flex gap-2 flex-wrap">
              {task.tags.map((tag) => (
                <span
                  key={tag}
                  className="px-2.5 py-1 rounded-lg text-xs font-medium bg-glass-100 text-[hsl(var(--text-secondary))] border border-glass-200"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* S3 Attachments Section */}
        <div className="border-t border-[hsl(var(--border-subtle))] pt-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-[hsl(var(--text-primary))] flex items-center gap-2">
              <Paperclip className="w-4 h-4 text-emerald-400" /> Attachments
              {attachments.length > 0 && (
                <span className="text-xs font-normal text-[hsl(var(--text-muted))]">
                  ({attachments.length})
                </span>
              )}
            </h3>

            {/* Hidden File Input */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".jpg,.jpeg,.png,.webp,.pdf,image/jpeg,image/png,image/webp,application/pdf"
              className="hidden"
            />

            <GlassButton
              variant="ghost"
              size="sm"
              disabled={isUploading}
              onClick={() => fileInputRef.current?.click()}
              icon={
                isUploading ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Paperclip className="w-3.5 h-3.5" />
                )
              }
            >
              {isUploading ? "Uploading..." : "Attach File"}
            </GlassButton>
          </div>

          <p className="text-xs text-[hsl(var(--text-muted))] mb-3">
            Supported: JPEG, PNG, WebP (max 5 MB) or PDF (max 10 MB). Stored securely via Amazon S3.
          </p>

          {isLoadingAttachments ? (
            <div className="flex items-center justify-center py-6 text-sm text-[hsl(var(--text-muted))] gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading attachments...
            </div>
          ) : attachments.length === 0 ? (
            <div className="rounded-xl border border-dashed border-[hsl(var(--border-subtle))] p-6 text-center">
              <p className="text-xs text-[hsl(var(--text-muted))]">No attachments yet. Click above to attach a file.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {attachments.map((att) => (
                <div
                  key={att.id}
                  className="flex items-center justify-between p-3 rounded-xl bg-glass-100 border border-glass-200 hover:border-[hsl(var(--border))] transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0 flex-1">
                    {getFileIcon(att.mimeType)}
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium text-[hsl(var(--text-primary))] truncate">
                        {att.filename}
                      </p>
                      <p className="text-[10px] text-[hsl(var(--text-muted))]">
                        {formatBytes(att.size)} • {new Date(att.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  <GlassButton
                    variant="ghost"
                    size="sm"
                    disabled={downloadingId === att.id}
                    onClick={() => handleDownload(att)}
                    icon={
                      downloadingId === att.id ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Download className="w-3.5 h-3.5" />
                      )
                    }
                  >
                    Download
                  </GlassButton>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Comments placeholder */}
        <div className="border-t border-[hsl(var(--border-subtle))] pt-6">
          <h3 className="text-sm font-semibold text-[hsl(var(--text-primary))] flex items-center gap-2 mb-4">
            <MessageSquare className="w-4 h-4" /> Comments
          </h3>
          <div className="space-y-3">
            <textarea
              placeholder="Add a comment..."
              className="glass-input w-full min-h-[80px] resize-none text-sm"
            />
            <GlassButton variant="primary" size="sm">Post Comment</GlassButton>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export default TaskDetail;
