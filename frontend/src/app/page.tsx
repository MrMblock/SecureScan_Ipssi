import Navbar from '@/components/landing/Navbar'
import Hero from '@/components/landing/Hero'
import TrustedTools from '@/components/landing/TrustedTools'
import Stats from '@/components/landing/Stats'
import Features from '@/components/landing/Features'
import HowItWorks from '@/components/landing/HowItWorks'
import CodePreview from '@/components/landing/CodePreview'
import OWASPGrid from '@/components/landing/OWASPGrid'
import FAQ from '@/components/landing/FAQ'
import Footer from '@/components/landing/Footer'

export default function Home() {
  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <TrustedTools />
        <Stats />
        <Features />
        <HowItWorks />
        <CodePreview />
        <OWASPGrid />
        <FAQ />
      </main>
      <Footer />
    </>
  )
}
