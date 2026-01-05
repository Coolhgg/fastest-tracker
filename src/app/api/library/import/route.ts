import { prisma } from "@/lib/prisma"
import { NextRequest, NextResponse } from "next/server"
import { checkRateLimit, getClientIp, handleApiError, ApiError, ErrorCodes } from "@/lib/api-utils"
import { createClient } from "@/lib/supabase/server"
import { processImportJob } from "@/lib/sync/import-pipeline"

export async function POST(request: NextRequest) {
  try {
    const ip = getClientIp(request);
    if (!await checkRateLimit(`library-import:${ip}`, 5, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED);
    }

    const { source, entries } = await request.json();

    if (!source || !entries || !Array.isArray(entries)) {
      throw new ApiError("Invalid import data", 400, ErrorCodes.INVALID_INPUT);
    }

    // Create the import job
    const job = await prisma.importJob.create({
      data: {
        user_id: user.id,
        source: source,
        status: "pending",
        total_items: entries.length,
        processed_items: 0,
        matched_items: 0,
        failed_items: 0,
        error_log: entries // Store entries in error_log temporarily for processing
      }
    });

    // Trigger processing asynchronously
    // In a real production app, this would be a BullMQ job
    // Here we run it in the background of the serverless function (Vercel allows this for a short time)
    // or we just fire and forget if the environment supports it.
    processImportJob(job.id).catch(err => {
      console.error(`Import job ${job.id} failed:`, err);
    });

    return NextResponse.json({ 
      success: true, 
      job_id: job.id,
      message: "Import started" 
    });
  } catch (error) {
    return handleApiError(error);
  }
}

export async function GET(request: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED);
    }

    const { searchParams } = new URL(request.url);
    const jobId = searchParams.get("id");

    if (jobId) {
      const job = await prisma.importJob.findUnique({
        where: { id: jobId, user_id: user.id }
      });
      return NextResponse.json(job);
    }

    const jobs = await prisma.importJob.findMany({
      where: { user_id: user.id },
      orderBy: { created_at: "desc" },
      limit: 10
    });

    return NextResponse.json(jobs);
  } catch (error) {
    return handleApiError(error);
  }
}
