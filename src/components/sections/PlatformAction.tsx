"use client";

import React from 'react';
import Image from 'next/image';

const PlatformAction = () => {
  return (
    <section className="mx-5 2xl:mx-0 py-16 lg:py-24">
      <div className="container relative overflow-hidden rounded-[2.5rem] bg-[#111827] text-white min-h-[600px] lg:min-h-[700px]">
        {/* Scenic Background Image */}
        <div className="absolute inset-0 z-0">
          <img
            src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/platform-bg-10.png"
            alt="Platform background"
            className="w-full h-full object-cover opacity-60 pointer-events-none"
          />
          {/* Overlay to ensure text readability */}
          <div className="absolute inset-0 bg-gradient-to-r from-[#111827]/90 via-[#111827]/60 to-transparent" />
        </div>

        {/* Content Wrapper */}
        <div className="relative z-10 p-8 lg:p-16 flex flex-col h-full">
          {/* Header Section */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-16 gap-6">
            <div>
              <h2 className="text-3xl lg:text-[2.5rem] font-bold leading-tight mb-2">
                See the platform in action.<br className="hidden sm:block" />
                <span className="text-[#9CA3AF] font-normal text-xl lg:text-2xl mt-1 block sm:inline sm:mt-0">
                  {" "}Start tracking in under 1 minute.
                </span>
              </h2>
            </div>
            <button className="bg-white text-[#111827] px-6 py-2.5 rounded-lg font-semibold text-sm hover:bg-gray-100 transition-all whitespace-nowrap shadow-sm">
              Get started for free
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-12 lg:gap-20 items-center">
            {/* Left Column: Features */}
            <div className="flex flex-col gap-10">
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <img
                    src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/bookmark-icon-3.svg"
                    alt="Bookmark"
                    className="w-8 h-8"
                  />
                  <h4 className="text-xl font-semibold">Take Control of Your Collection</h4>
                </div>
                <p className="text-[#9CA3AF] text-base leading-relaxed max-w-md">
                  Sort it, filter it, tag it—make your library truly yours. Add notes, drop ratings, or create custom tags to keep track of everything exactly how you like it.
                </p>
                <p className="text-[#9CA3AF] text-base leading-relaxed max-w-md">
                  Managing your collection just got a whole lot easier (and way more fun).
                </p>
              </div>

              {/* Smaller Feature List */}
              <div className="border-t border-white/10 pt-8 space-y-6">
                <div className="flex items-center gap-4 group">
                  <div className="w-10 h-10 flex items-center justify-center rounded-lg bg-white/5 group-hover:bg-white/10 transition-colors">
                    <img
                      src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/platform-filter-icon-4.svg"
                      alt="Filter"
                      className="w-5 h-5"
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-200">Filter by genres, tags, reading status</span>
                </div>

                <div className="flex items-center gap-4 group">
                  <div className="w-10 h-10 flex items-center justify-center rounded-lg bg-white/5 group-hover:bg-white/10 transition-colors">
                    <img
                      src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/platform-notes-icon-5.svg"
                      alt="Notes"
                      className="w-5 h-5"
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-200">Add notes, rate titles, and create tags</span>
                </div>

                <div className="flex items-center gap-4 group">
                  <div className="w-10 h-10 flex items-center justify-center rounded-lg bg-white/5 group-hover:bg-white/10 transition-colors">
                    <img
                      src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/platform-history-icon-6.svg"
                      alt="History"
                      className="w-5 h-5"
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-200">Keep a detailed history</span>
                </div>
              </div>
            </div>

            {/* Right Column: Large Preview Image */}
            <div className="lg:col-span-2 h-full lg:relative">
              <div className="relative rounded-2xl overflow-hidden border border-white/10 shadow-[0_30px_60px_-15px_rgba(0,0,0,0.5)] bg-[#1F2937]/50 backdrop-blur-sm lg:translate-x-12">
                <img
                  src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/platform-11.jpg"
                  alt="Kenmei platform interface"
                  className="w-full h-auto object-cover"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default PlatformAction;