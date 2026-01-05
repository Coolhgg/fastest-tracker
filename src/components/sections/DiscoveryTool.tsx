"use client";

import React from 'react';
import Image from 'next/image';

const DiscoveryTool: React.FC = () => {
  return (
    <section 
      id="discover" 
      className="py-24 bg-white"
    >
      <div className="container px-5 md:px-10 mx-auto max-w-[1280px]">
        {/* Header Section */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-16 gap-6">
          <div>
            <h2 className="text-[40px] font-bold leading-[1.2] text-[#111827]">
              The Ultimate Tracking Tool.
              <br className="hidden sm:block" />
              <span className="font-normal text-[#6b7280]"> Your taste, our picks—perfect match.</span>
            </h2>
          </div>
          <a href="/discovery">
            <button className="bg-[#313131] text-white px-8 py-3 rounded-lg font-semibold text-sm hover:bg-black transition-all shadow-sm">
              Start discovering
            </button>
          </a>
        </div>

        {/* Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-10 lg:gap-20">
          
          {/* Left Column: Features */}
          <div className="flex flex-col justify-between">
            {/* Main Highlight */}
            <div className="pb-10">
              <div className="flex items-center gap-3 mb-4">
                <Image 
                  src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/light-sparkles-icon-7.svg" 
                  alt="Sparkles icon" 
                  width={32} 
                  height={32}
                  className="w-8 h-8"
                />
                <h4 className="text-xl font-semibold text-[#111827]">From hidden gems to trending hits</h4>
              </div>
              <p className="text-[#6b7280] text-base leading-relaxed mb-4">
                Say goodbye to endless scrolling and hello to smarter recommendations. Whether you're searching for trending titles, hidden gems, or something completely fresh, our discovery tools have your back.
              </p>
              <p className="text-[#6b7280] text-base leading-relaxed">
                Discover your next obsession with precision filtering across genres, tags, platforms and more.
              </p>
            </div>

            {/* Sub-features Accordion-style List */}
            <div className="divide-y border-t border-b mb-10 lg:mb-24">
              <div className="flex items-center gap-4 py-5 group cursor-default">
                <div className="w-8 h-8 flex items-center justify-center rounded-md bg-[#f9fafb]">
                  <Image 
                    src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/light-flame-icon-9.svg" 
                    alt="Flame icon" 
                    width={16} 
                    height={16}
                  />
                </div>
                <h4 className="text-sm font-semibold text-[#111827]">Discover what's hot right now</h4>
              </div>
              
              <div className="flex items-center gap-4 py-5 group cursor-default">
                <div className="w-8 h-8 flex items-center justify-center rounded-md bg-[#f9fafb]">
                  <Image 
                    src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/light-search-icon-11.svg" 
                    alt="Search icon" 
                    width={16} 
                    height={16}
                  />
                </div>
                <h4 className="text-sm font-semibold text-[#111827]">Uncover hidden gems</h4>
              </div>

              <div className="flex items-center gap-4 py-5 group cursor-default">
                <div className="w-8 h-8 flex items-center justify-center rounded-md bg-[#f9fafb]">
                  <Image 
                    src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/light-filters-icon-13.svg" 
                    alt="Filters icon" 
                    width={16} 
                    height={16}
                  />
                </div>
                <h4 className="text-sm font-semibold text-[#111827] leading-tight">Refine using tags, genres, and other advanced filters</h4>
              </div>
            </div>
          </div>

          {/* Right Column: Platform Preview */}
          <div className="lg:col-span-2 relative overflow-hidden rounded-2xl border border-[#e5e7eb] shadow-[0_10px_15px_-3px_rgba(0,0,0,0.1)]">
            <Image 
              src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/light-discovery-section-12.jpg" 
              alt="Discovery Interface Preview" 
              width={1600} 
              height={1000}
              className="w-full h-full object-cover object-left-top"
              priority
            />
          </div>

        </div>
      </div>
    </section>
  );
};

export default DiscoveryTool;