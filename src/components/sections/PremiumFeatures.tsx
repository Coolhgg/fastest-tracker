"use client";

import React from 'react';
import Image from 'next/image';

const PremiumFeatures = () => {
  return (
    <section 
      id="premium" 
      className="container py-[120px] bg-white"
      style={{
        maxWidth: '1280px',
        margin: '0 auto',
      }}
    >
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end mb-16 gap-6">
        <div>
          <h2 className="text-[2.5rem] font-bold leading-[1.2] tracking-[-0.02em] text-[#111827]">
            Go Premium & Unlock More.<br className="hidden sm:block" />
            <span className="font-normal text-[#6B7280]"> Supercharge Your Tracking Experience.</span>
          </h2>
        </div>
        <a href="/pricing">
          <button className="bg-[#313131] hover:bg-black text-white px-6 py-2.5 rounded-lg font-semibold text-sm transition-all shadow-sm">
            Explore premium
          </button>
        </a>
      </div>

      {/* 3-Column Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
        
        {/* Personalized Recommendations Card */}
        <div className="flex flex-col">
          <div className="relative aspect-[4/3] mb-6 overflow-hidden rounded-xl border border-[#E5E7EB] shadow-[0_10px_15px_-3px_rgba(0,0,0,0.1)]">
            <Image
              src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/light-personalized-reccs-14.jpg"
              alt="Personalized recommendations"
              fill
              className="object-cover"
              sizes="(max-width: 768px) 100vw, 33vw"
            />
          </div>
          <div className="flex flex-col gap-2">
            <h4 className="text-[1.25rem] font-semibold text-[#111827] leading-tight">
              Personalized Recommendations
            </h4>
            <p className="text-[#6B7280] text-base leading-relaxed">
              The more you read, the better we get at suggesting series you&apos;ll love—tailored for you.
            </p>
          </div>
        </div>

        {/* Smart Suggestions System Card */}
        <div className="flex flex-col">
          <div className="relative aspect-[4/3] mb-6 overflow-hidden rounded-xl border border-[#E5E7EB] shadow-[0_10px_15px_-3px_rgba(0,0,0,0.1)]">
            <Image
              src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/light-smart-suggestions-15.jpg"
              alt="Smart suggestions system"
              fill
              className="object-cover"
              sizes="(max-width: 768px) 100vw, 33vw"
            />
          </div>
          <div className="flex flex-col gap-2">
            <h4 className="text-[1.25rem] font-semibold text-[#111827] leading-tight">
              Smart Suggestions System
            </h4>
            <p className="text-[#6B7280] text-base leading-relaxed">
              Get real-time notifications and tailored suggestions to keep your list organized and up to date.
            </p>
          </div>
        </div>

        {/* And More / Custom Collection Management Card */}
        <div className="flex flex-col">
          <div className="relative aspect-[4/3] mb-6 overflow-hidden rounded-xl border border-[#E5E7EB] shadow-[0_10px_15px_-3px_rgba(0,0,0,0.1)] bg-[#F9FAFB]">
            <div className="p-6 h-full flex flex-col justify-center">
              {/* This represents the "Customise Collections" UI element shown in screenshots */}
              <div className="bg-white rounded-lg border border-[#E5E7EB] p-4 shadow-sm">
                <p className="text-[10px] font-bold text-gray-800 mb-3 ml-2">Customise Collections</p>
                <div className="space-y-2">
                  <div className="flex items-center gap-2 px-2 py-1.5 bg-gray-50 rounded border border-dashed border-gray-200">
                    <div className="w-2 h-2 bg-gray-300 rounded-sm"></div>
                    <div className="h-2 w-24 bg-gray-200 rounded"></div>
                  </div>
                  <div className="flex items-center gap-2 px-2 py-1.5 border border-dashed border-gray-100 opacity-60">
                    <div className="w-2 h-2 bg-gray-200 rounded-sm"></div>
                    <div className="h-2 w-20 bg-gray-100 rounded"></div>
                  </div>
                  <div className="flex items-center gap-2 px-2 py-1.5 border border-dashed border-gray-100 opacity-40">
                    <div className="w-2 h-2 bg-gray-100 rounded-sm"></div>
                    <div className="h-2 w-28 bg-gray-50 rounded"></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <h4 className="text-[1.25rem] font-semibold text-[#111827] leading-tight">
              And More...
            </h4>
            <p className="text-[#6B7280] text-base leading-relaxed">
              From profile customization to early access features, level-up your experience even more.
            </p>
          </div>
        </div>

      </div>
    </section>
  );
};

export default PremiumFeatures;