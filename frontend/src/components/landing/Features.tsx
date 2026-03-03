'use client'
import Link from 'next/link'
import Image from 'next/image'
import React, { useRef } from 'react'
import { motion, useInView } from 'motion/react'
import { useTranslation } from '@/i18n'

export default function Features() {
  const { t } = useTranslation()
  const ref = useRef(null)
  const inView = useInView(ref)

  const bottomAnimation = (index: number) => ({
    initial: { y: '25%', opacity: 0 },
    animate: inView ? { y: 0, opacity: 1 } : { y: '25%', opacity: 0 },
    transition: { duration: 0.3, delay: 0.3 + index * 0.15 },
  })

  return (
    <section id='services'>
      <div ref={ref} className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='flex flex-col gap-12'>
            <div className='flex flex-col justify-center items-center gap-10 lg:gap-16'>
              <motion.div
                {...bottomAnimation(0)}
                className='max-w-2xl text-center'>
                <h2>
                  {t('landing.features.title')}{' '}
                  <span className='instrument-font italic font-normal text-white/70'>
                    {t('landing.features.titleHighlight')}
                  </span>
                </h2>
              </motion.div>

              {/* Bento grid */}
              <motion.div {...bottomAnimation(1)} className='w-full'>
                <div className='grid grid-cols-1 md:grid-cols-3 grid-rows-2 gap-4'>

                  {/* Card 1 — grande, avec image (col-span-2) */}
                  <div className='relative md:col-span-2 rounded-3xl overflow-hidden bg-card_bg border border-white/10 min-h-[340px] flex flex-col justify-end'>
                    <Image
                      src='https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=900&auto=format&fit=crop'
                      alt='Analyse de code'
                      fill
                      className='object-cover opacity-40'
                      unoptimized
                    />
                    <div className='relative z-10 p-8 flex flex-col gap-3'>
                      <span className='text-xs font-semibold tracking-widest text-accent uppercase'>
                        {t('landing.features.card1Tag')}
                      </span>
                      <h4 className='text-white text-xl md:text-2xl font-semibold leading-snug'>
                        {t('landing.features.card1Title').split('\n').map((line, i) => (
                          <React.Fragment key={i}>{i > 0 && <br />}{line}</React.Fragment>
                        ))}
                      </h4>
                    </div>
                  </div>

                  {/* Card 2 — stat */}
                  <div className='rounded-3xl bg-blue_gradient border border-accent/20 flex flex-col justify-center gap-4 p-8'>
                    <span className='text-xs font-semibold tracking-widest text-accent/70 uppercase'>
                      {t('landing.features.card2Tag')}
                    </span>
                    <p className='text-7xl font-bold leading-none text-white'>
                      {t('landing.features.card2Stat')}<span className='text-4xl text-accent'>%</span>
                    </p>
                    <p className='text-white/60 text-sm leading-relaxed'>
                      {t('landing.features.card2Desc')}
                    </p>
                  </div>

                  {/* Card 3 — petite avec image */}
                  <div className='relative rounded-3xl overflow-hidden bg-card_bg border border-white/10 min-h-[260px] flex flex-col justify-end'>
                    <Image
                      src='https://images.unsplash.com/photo-1504639725590-34d0984388bd?w=500&auto=format&fit=crop'
                      alt='Sécurité'
                      fill
                      className='object-cover opacity-30'
                      unoptimized
                    />
                    <div className='relative z-10 p-6 flex flex-col gap-2'>
                      <span className='text-xs font-semibold tracking-widest text-accent uppercase'>
                        {t('landing.features.card3Tag')}
                      </span>
                      <p className='text-white font-medium leading-snug'>
                        {t('landing.features.card3Desc')}
                      </p>
                    </div>
                  </div>

                  {/* Card 4 — grande texte (col-span-2) */}
                  <div className='md:col-span-2 rounded-3xl bg-card_bg_light border border-white/10 flex flex-col justify-between gap-6 p-8'>
                    <span className='text-xs font-semibold tracking-widest text-accent uppercase'>
                      {t('landing.features.card4Tag')}
                    </span>
                    <p className='text-white text-xl md:text-3xl font-medium leading-snug'>
                      &ldquo;{t('landing.features.card4Quote')}&rdquo;
                    </p>
                    <div>
                      <p className='text-white text-sm font-semibold'>{t('landing.features.card4Author')}</p>
                      <p className='text-white/50 text-sm'>{t('landing.features.card4Sub')}</p>
                    </div>
                  </div>

                </div>
              </motion.div>
            </div>

            {/* CTA bar */}
            <motion.div
              {...bottomAnimation(2)}
              className='flex flex-col gap-4 xl:flex xl:flex-row bg-card_bg border border-white/10 items-center justify-between py-8 px-7 sm:px-12 rounded-3xl w-full'>
              <h4 className='text-white text-center xl:text-left'>
                {t('landing.features.ctaTitle')}
                <br /> {t('landing.features.ctaSubtitle')}
              </h4>
              <div className='flex flex-col sm:flex-row gap-3 items-center'>
                <Link
                  href='/dashboard'
                  className='group overflow-hidden gap-2 text-black font-medium bg-white rounded-full flex items-center lg:gap-4 py-2 pl-5 pr-2 border border-white/50 hover:bg-transparent hover:text-white transition-all duration-200 ease-in-out'>
                  <span className='group-hover:translate-x-12 transform transition-transform duration-200 ease-in-out'>
                    {t('landing.features.ctaButton')}
                  </span>
                  <svg
                    width='32'
                    height='32'
                    viewBox='0 0 32 32'
                    fill='none'
                    xmlns='http://www.w3.org/2000/svg'
                    className='group-hover:-translate-x-40 transition-all duration-200 ease-in-out'>
                    <rect
                      width='32'
                      height='32'
                      rx='16'
                      fill='#1B1D1E'
                      className='transition-colors duration-200 ease-in-out group-hover:fill-white'
                    />
                    <path
                      d='M11.832 11.3335H20.1654M20.1654 11.3335V19.6668M20.1654 11.3335L11.832 19.6668'
                      stroke='white'
                      strokeWidth='1.42857'
                      strokeLinecap='round'
                      strokeLinejoin='round'
                      className='group-hover:stroke-black'
                    />
                  </svg>
                </Link>
                <a
                  href='https://github.com/MrMblock/SecureScan'
                  target='_blank'
                  rel='noopener noreferrer'
                  className='group overflow-hidden border border-white/50 text-white font-medium bg-transparent gap-2 rounded-full flex items-center justify-between lg:gap-4 py-2 pl-5 pr-2 hover:opacity-95 transition-all duration-200 ease-in-out'>
                  <span className='group-hover:translate-x-12 transform transition-transform duration-200 ease-in-out'>
                    {t('landing.features.ctaGithub')}
                  </span>
                  <svg
                    width='32'
                    height='32'
                    viewBox='0 0 32 32'
                    fill='none'
                    xmlns='http://www.w3.org/2000/svg'
                    className='group-hover:-translate-x-36 transition-all duration-200 ease-in-out'>
                    <rect width='32' height='32' rx='16' fill='white' />
                    <path
                      d='M11.832 11.3334H20.1654M20.1654 11.3334V19.6668M20.1654 11.3334L11.832 19.6668'
                      stroke='#1B1D1E'
                      strokeWidth='1.42857'
                      strokeLinecap='round'
                      strokeLinejoin='round'
                    />
                  </svg>
                </a>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}
