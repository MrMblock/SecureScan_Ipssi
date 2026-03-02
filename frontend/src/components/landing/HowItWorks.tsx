'use client'
import React from 'react'
import { useTranslation } from '@/i18n'
import fr from '@/i18n/locales/fr.json'
import en from '@/i18n/locales/en.json'

export default function HowItWorks() {
  const { t, locale } = useTranslation()

  const translations = locale === 'en' ? en : fr
  const steps = translations.landing.howItWorks.steps

  return (
    <section id='pipeline'>
      <div className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='flex flex-col gap-12'>
            <div className='max-w-xl mx-auto text-center'>
              <h2>
                {t('landing.howItWorks.title')}{' '}
                <span className='instrument-font italic font-normal text-white/70'>
                  {t('landing.howItWorks.titleHighlight')}
                </span>
              </h2>
              <p className='text-white/60 mt-4'>
                {t('landing.howItWorks.subtitle')}
              </p>
            </div>

            <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5'>
              {steps.map((step) => (
                <div
                  key={step.num}
                  className='group flex flex-col gap-3 p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 transition-all duration-300'>
                  <div className='flex items-center justify-between'>
                    <span className='text-xs font-bold px-2.5 py-1 rounded-full bg-accent/10 text-accent'>
                      {t('landing.howItWorks.stepLabel')} {step.num}
                    </span>
                  </div>
                  <h5>{step.title}</h5>
                  <p className='text-white/60 text-sm leading-relaxed'>
                    {step.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
