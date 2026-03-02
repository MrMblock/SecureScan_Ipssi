'use client'
import React from 'react'
import { useTranslation } from '@/i18n'
import fr from '@/i18n/locales/fr.json'
import en from '@/i18n/locales/en.json'

const CATEGORY_STYLES: Record<string, { color: string; badge?: string }> = {
  A01: { color: '#ef4444', badge: 'priority' },
  A02: { color: '#f97316', badge: 'priority' },
  A03: { color: '#f97316', badge: '2025' },
  A04: { color: '#eab308' },
  A05: { color: '#ef4444', badge: 'priority' },
  A06: { color: '#eab308' },
  A07: { color: '#f97316' },
  A08: { color: '#eab308' },
  A09: { color: '#3b82f6' },
  A10: { color: '#eab308', badge: '2025' },
}

export default function OWASPGrid() {
  const { t, locale } = useTranslation()
  const translations = locale === 'en' ? en : fr

  const categories = translations.landing.owasp.categories

  return (
    <section id='owasp'>
      <div className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='flex flex-col gap-12'>
            <div className='max-w-xl mx-auto text-center'>
              <h2>
                {t('landing.owasp.title')}{' '}
                <span className='instrument-font italic font-normal text-white/70'>
                  {t('landing.owasp.titleHighlight')}
                </span>
              </h2>
              <p className='text-white/60 mt-4'>
                {t('landing.owasp.subtitle')}
              </p>
            </div>

            <div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
              {categories.map((cat) => {
                const style = CATEGORY_STYLES[cat.id] ?? { color: '#eab308' }
                const badgeLabel =
                  style.badge === 'priority'
                    ? t('landing.owasp.priority')
                    : style.badge === '2025'
                    ? t('landing.owasp.badge2025')
                    : undefined

                return (
                  <div
                    key={cat.id}
                    className='group flex items-start gap-4 p-5 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 transition-all duration-300'>
                    {/* ID badge */}
                    <div
                      className='shrink-0 w-14 h-14 rounded-xl flex flex-col items-center justify-center text-xs font-bold'
                      style={{ backgroundColor: `${style.color}10`, color: style.color }}>
                      <span className='text-[10px] opacity-70'>{cat.id}</span>
                      <span
                        className='w-6 h-1 rounded-full mt-1'
                        style={{ backgroundColor: style.color }}
                      />
                    </div>

                    {/* Content */}
                    <div className='flex-1 min-w-0'>
                      <div className='flex items-center gap-2 mb-1'>
                        <h6 className='text-white font-medium text-sm'>
                          {cat.name}
                        </h6>
                        {badgeLabel && (
                          <span
                            className='text-[10px] font-bold px-1.5 py-0.5 rounded'
                            style={{ backgroundColor: `${style.color}15`, color: style.color }}>
                            {badgeLabel}
                          </span>
                        )}
                      </div>
                      <p className='text-white/50 text-xs leading-relaxed'>
                        {cat.desc}
                      </p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
