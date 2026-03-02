'use client'
import Link from 'next/link'
import Image from 'next/image'
import { useTranslation } from '@/i18n'

export default function Footer() {
  const { t } = useTranslation()

  const footerLinks = [
    {
      title: t('landing.footer.product'),
      links: [
        { name: t('landing.footer.productLinks.dashboard'), url: '/dashboard' },
        { name: t('landing.footer.productLinks.scanner'), url: '/dashboard' },
        { name: t('landing.footer.productLinks.reports'), url: '/dashboard' },
      ],
    },
    {
      title: t('landing.footer.resources'),
      links: [
        { name: t('landing.footer.resourceLinks.owasp'), url: 'https://owasp.org/Top10/' },
        { name: t('landing.footer.resourceLinks.semgrep'), url: 'https://semgrep.dev/docs/' },
        { name: t('landing.footer.resourceLinks.docs'), url: 'https://github.com/MrMblock/SecureScan' },
      ],
    },
    {
      title: t('landing.footer.project'),
      links: [
        { name: t('landing.footer.projectLinks.github'), url: 'https://github.com/MrMblock/SecureScan' },
        { name: t('landing.footer.projectLinks.contribute'), url: 'https://github.com/MrMblock/SecureScan' },
      ],
    },
  ]

  return (
    <footer className='xl:pt-20 pb-6'>
      <div className='container'>
        <div className='flex flex-col xl:flex-row py-16 gap-10 justify-between border-b border-white/10'>
          <div className='flex flex-col gap-6 max-w-md'>
            {/* Logo */}
            <Link href='/' className='flex items-center gap-2'>
              <Image src='/logo.png' alt='SecureScan' width={200} height={56} className='h-12 w-auto' />
            </Link>
            <p className='text-white/60'>
              {t('landing.footer.description')}
            </p>
            <div className='flex gap-4'>
              <a
                href='https://github.com/MrMblock/SecureScan'
                target='_blank'
                rel='noopener noreferrer'
                className='text-white/40 hover:text-white/60 transition-colors'>
                <svg width='20' height='20' viewBox='0 0 24 24' fill='currentColor'>
                  <path d='M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z' />
                </svg>
              </a>
            </div>
          </div>
          <div className='grid sm:grid-cols-3 gap-6'>
            {footerLinks.map((col) => (
              <div key={col.title} className='flex flex-col gap-4'>
                <p className='font-medium'>{col.title}</p>
                <ul className='flex flex-col gap-3'>
                  {col.links.map((link) => (
                    <li
                      key={link.name}
                      className='text-white/60 hover:text-white transition-colors'>
                      <a
                        href={link.url}
                        target={link.url.startsWith('http') ? '_blank' : undefined}
                        rel={link.url.startsWith('http') ? 'noopener noreferrer' : undefined}>
                        {link.name}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
        <div className='flex justify-center mt-8'>
          <p className='text-white/60 text-sm'>
            &copy; {new Date().getFullYear()} {t('landing.footer.copyright')}
          </p>
        </div>
      </div>
    </footer>
  )
}
