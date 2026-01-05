import { redirect } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'
import Header from '@/components/sections/Header'
import Hero from '@/components/sections/Hero'
import CrossSiteTracking from '@/components/sections/CrossSiteTracking'
import PlatformAction from '@/components/sections/PlatformAction'
import DiscoveryTool from '@/components/sections/DiscoveryTool'
import SocialFeatures from '@/components/sections/SocialFeatures'
import PremiumFeatures from '@/components/sections/PremiumFeatures'
import CTASection from '@/components/sections/CTASection'
import Footer from '@/components/sections/Footer'

export default async function Home() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  if (user) {
    redirect('/library')
  }

  return (
    <div className="flex flex-col min-h-screen bg-background text-foreground transition-colors duration-300">
      <Header />
      <main>
        <Hero />
        <CrossSiteTracking />
        <PlatformAction />
        <DiscoveryTool />
        <SocialFeatures />
        <PremiumFeatures />
        <CTASection />
      </main>
      <Footer />
    </div>
  )
}
