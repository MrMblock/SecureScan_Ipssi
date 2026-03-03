'use client'
import Link from 'next/link'
import Image from 'next/image'
import { useEffect, useState } from 'react'
import { useTranslation } from '@/i18n'
import LanguageSwitcher from '@/components/common/LanguageSwitcher'

export default function Navbar() {
  const { t } = useTranslation()
  const [sticky, setSticky] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    const handleScroll = () => setSticky(window.scrollY >= 80)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const navLinks = [
    { label: t('nav.features'), href: '#services' },
    { label: t('nav.owasp'), href: '#owasp' },
    { label: t('nav.pipeline'), href: '#pipeline' },
    { label: t('nav.faq'), href: '#faq' },
  ]

  return (
    <header className='fixed top-0 z-50 w-full'>
      <div className='container p-3'>
        <nav
          className={`flex items-center py-3 px-4 justify-between transition-all duration-300 ${
            sticky ? 'rounded-full shadow-sm bg-card_bg/95 backdrop-blur-xl border border-white/5' : ''
          }`}>
          {/* Logo */}
          <Link href='/' className='flex items-center gap-2 flex-1'>
            <Image src='/logo.png' alt='SecureScan' width={200} height={56} className='h-12 w-auto' />
          </Link>

          {/* Desktop nav */}
          <div className='hidden lg:flex bg-white/5 rounded-3xl py-3 px-1'>
            <ul className='flex gap-1.5'>
              {navLinks.map((item) => (
                <li key={item.href}>
                  <a
                    href={item.href}
                    className='text-sm text-white/60 hover:text-white px-4 py-1.5 rounded-full hover:bg-white/5 transition-all duration-200'>
                    {item.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* CTA */}
          <div className='flex items-center gap-2 flex-1 justify-end'>
            <div className='hidden lg:block'>
              <LanguageSwitcher />
            </div>
            <Link
              href='/login'
              className='hidden lg:block bg-transparent border border-white/20 text-white/80 px-4 py-2 rounded-full text-sm hover:bg-white/5 transition-all duration-200'>
              {t('nav.login')}
            </Link>
            <Link
              href='/signup'
              className='hidden lg:block text-white px-4 py-2 bg-accent rounded-full text-sm hover:opacity-90 transition-all duration-200'>
              {t('nav.startScan')}
            </Link>

            {/* Mobile hamburger */}
            <button
              className='lg:hidden text-white'
              onClick={() => setSidebarOpen(!sidebarOpen)}>
              <svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'>
                <path fill='none' stroke='currentColor' strokeLinecap='round' strokeMiterlimit='10' strokeWidth='1.5' d='M4.5 12h15m-15 5.77h15M4.5 6.23h15' />
              </svg>
            </button>
          </div>
        </nav>
      </div>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className='fixed top-0 left-0 w-full h-full bg-black/50 z-40' onClick={() => setSidebarOpen(false)} />
      )}

      {/* Mobile sidebar */}
      <div
        className={`lg:hidden fixed top-0 right-0 h-full w-full bg-body_bg shadow-lg transform transition-transform duration-300 max-w-xs ${
          sidebarOpen ? 'translate-x-0' : 'translate-x-full'
        } z-50`}>
        <div className='flex items-center justify-between p-4'>
          <h5 className='font-bold'>{t('common.menu')}</h5>
          <button onClick={() => setSidebarOpen(false)}>
            <svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'>
              <path fill='none' stroke='currentColor' strokeLinecap='round' strokeLinejoin='round' strokeWidth='2' d='M6 18L18 6M6 6l12 12' />
            </svg>
          </button>
        </div>
        <ul className='flex flex-col p-4 gap-2'>
          <li className='py-2 px-3'>
            <LanguageSwitcher />
          </li>
          {navLinks.map((item) => (
            <li key={item.href}>
              <a
                href={item.href}
                className='block text-white/60 hover:text-white py-2 px-3 rounded-lg hover:bg-white/5 transition-all'
                onClick={() => setSidebarOpen(false)}>
                {item.label}
              </a>
            </li>
          ))}
          <Link
            href='/login'
            className='mt-3 border border-white/20 text-white/80 px-4 py-2.5 rounded-full text-sm text-center'
            onClick={() => setSidebarOpen(false)}>
            {t('nav.login')}
          </Link>
          <Link
            href='/signup'
            className='mt-1 text-white px-4 py-2.5 bg-accent rounded-full text-sm text-center'
            onClick={() => setSidebarOpen(false)}>
            {t('nav.startScan')}
          </Link>
        </ul>
      </div>
    </header>
  )
}
