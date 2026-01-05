import { prisma } from "@/lib/prisma";
import { ImportEntry, matchSeries, normalizeStatus, reconcileEntry } from "./import-matcher";

export async function processImportJob(jobId: string) {
  const job = await prisma.importJob.findUnique({
    where: { id: jobId },
    include: { user: true }
  });

  if (!job || job.status !== "pending") return;

  await prisma.importJob.update({
    where: { id: jobId },
    data: { status: "processing" }
  });

  const rawEntries = job.error_log as any[] || []; // Assuming entries are temporarily stored here
  const results = {
    matched: 0,
    failed: 0,
    skipped: [] as any[]
  };

  for (const entry of rawEntries) {
    try {
      const match = await matchSeries(entry);
      
      if (match.series_id) {
        const normalizedStatus = normalizeStatus(entry.status);
        
        // Find existing entry to apply conflict resolution
        const existingEntry = await prisma.libraryEntry.findUnique({
          where: {
            user_id_series_id: {
              user_id: job.user_id,
              series_id: match.series_id
            }
          }
        });

          if (existingEntry) {
            const reconciliation = reconcileEntry(
              { 
                status: existingEntry.status, 
                progress: Number(existingEntry.last_read_chapter || 0),
                last_updated: existingEntry.updated_at
              },
              { 
                status: normalizedStatus, 
                progress: entry.progress,
                last_updated: entry.last_updated
              }
            );


          if (reconciliation.shouldUpdate && reconciliation.updateData) {
            await prisma.libraryEntry.update({
              where: { id: existingEntry.id },
              data: {
                ...reconciliation.updateData,
                last_read_chapter: reconciliation.updateData.progress,
                updated_at: new Date()
              }
            });
            results.matched++;
          } else {
            results.skipped.push({
              title: entry.title,
              reason: reconciliation.reason || "Conflict resolution skipped update"
            });
          }
        } else {
          // New entry
          await prisma.libraryEntry.create({
            data: {
              user_id: job.user_id,
              series_id: match.series_id,
              status: normalizedStatus,
              last_read_chapter: entry.progress,
              added_at: new Date()
            }
          });
          results.matched++;
        }
      } else {
        results.failed++;
        results.skipped.push({
          title: entry.title,
          reason: "No confident match found"
        });
      }

      // Update progress
      await prisma.importJob.update({
        where: { id: jobId },
        data: {
          processed_items: { increment: 1 },
          matched_items: results.matched,
          failed_items: results.failed
        }
      });
    } catch (error: any) {
      results.failed++;
      results.skipped.push({
        title: entry.title,
        reason: error.message
      });
    }
  }

  await prisma.importJob.update({
    where: { id: jobId },
    data: {
      status: "completed",
      completed_at: new Date(),
      error_log: results.skipped // Record failures for user report
    }
  });

  // Log audit event
  await prisma.auditLog.create({
    data: {
      user_id: job.user_id,
      event: "library_import_completed",
      status: "success",
      metadata: {
        job_id: jobId,
        matched: results.matched,
        failed: results.failed
      }
    }
  });
}
