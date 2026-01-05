"use client";

import React from 'react';
import Image from 'next/image';

const Footer = () => {
  const footerLinks = {
    Product: [
      { name: 'Supported Sites', href: '#' },
      { name: 'Pricing', href: '#' },
      { name: 'About', href: '#' },
    ],
    Resources: [
      { name: 'Suggestions', href: '#' },
      { name: 'Changelog', href: '#' },
      { name: 'Status', href: '#' },
      { name: 'Blog', href: '#' },
    ],
    Legal: [
      { name: 'Cookies', href: '#' },
      { name: 'Privacy', href: '#' },
      { name: 'Terms', href: '#' },
      { name: 'DMCA / Takedown', href: '#' },
    ],
    Social: [
      { name: 'Discord', href: '#' },
      { name: 'X', href: '#' },
    ],
  };

  return (
    <footer className="relative w-full bg-[#111827] text-white pt-24 overflow-hidden">
      {/* Landscape Background Image */}
      <div className="absolute inset-0 z-0">
        <Image
          src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/images/bg-footer-18.png"
          alt="Footer background"
          fill
          className="object-cover opacity-30"
          priority
        />
        {/* Gradient overlay to ensure text readability and blend with dark theme */}
        <div className="absolute inset-0 bg-gradient-to-t from-[#111827] via-transparent to-transparent pointer-events-none" />
      </div>

      <div className="container relative z-10 mx-auto px-5 lg:px-10">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 mb-20">
          {/* Logo and Tagline Column */}
          <div className="lg:col-span-5 flex flex-col items-start">
            <div className="mb-6">
              <Image
                src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/ea8c8153-f703-425a-ac39-2d781d32758e-kenmei-co/assets/svgs/light-logo-8ogL60VF-1.svg"
                alt="Kenmei logo"
                width={120}
                height={30}
                className="w-28 brightness-0 invert"
              />
            </div>
            <p className="text-gray-400 text-sm max-w-xs leading-relaxed font-medium">
              Your favourite tracker for discovering and tracking new series.
            </p>
          </div>

          {/* Links Columns */}
          <div className="lg:col-span-7">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              {Object.entries(footerLinks).map(([title, links]) => (
                <div key={title}>
                  <h4 className="text-white font-bold text-sm mb-5 tracking-wide">
                    {title}
                  </h4>
                  <ul className="space-y-3">
                    {links.map((link) => (
                      <li key={link.name}>
                        <a
                          href={link.href}
                          className="text-gray-400 hover:text-white transition-colors duration-200 text-sm font-medium"
                        >
                          {link.name}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer Bottom / Copyright */}
        <div className="border-t border-white/10 py-10 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="text-gray-500 text-xs font-medium">
            © 2025 Studio Shogun, LTD. All rights reserved.
          </div>
          <p className="text-gray-500 text-xs font-medium text-center md:text-right">
            We use cookies to improve your experience and provide core website functionality.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;