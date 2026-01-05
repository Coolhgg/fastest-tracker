"use client";

import React from 'react';
import Image from 'next/image';

const CTASection: React.FC = () => {
  return (
    <section className="relative w-full px-5 py-20 sm:px-10 lg:px-20">
      <div className="container mx-auto max-w-[1280px]">
        <div className="relative h-[480px] w-full overflow-hidden rounded-[2rem] sm:rounded-[3rem]">
          {/* Background Image */}
          <div className="absolute inset-0 z-0">
            <Image
              src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/bg-cta-17.png"
              alt="Scenic mountain landscape"
              fill
              className="object-cover object-center"
              priority
            />
            {/* Subtle overlay to ensure text readability if needed, though original seems clear */}
            <div className="absolute inset-0 bg-black/5"></div>
          </div>

          {/* Content */}
          <div className="relative z-10 flex h-full flex-col items-center justify-center text-center px-6">
            <h2 className="mb-8 max-w-2xl text-[2.5rem] font-bold leading-[1.2] tracking-tight text-white md:text-[3.5rem]">
              Ready for Your Next Favourite Read?
            </h2>
            
            <a
              href="#"
              className="inline-flex h-[52px] items-center justify-center rounded-xl bg-white px-8 text-sm font-semibold text-gray-900 shadow-lg transition-transform hover:scale-105 active:scale-95"
            >
              Get started for free
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};

export default CTASection;