'use client'
import Link from 'next/link'
import React from 'react'
import { motion } from 'motion/react'
import { useTranslation } from '@/i18n'

const bottomAnimation = {
  initial: { y: '20%', opacity: 0 },
  animate: { y: 0, opacity: 1 },
  transition: { duration: 1, delay: 0.8 },
}

export default function Hero() {
  const { t } = useTranslation()

  return (
    <section>
      <div className='relative w-full pt-44 2xl:pb-20 pb-10 before:absolute before:w-full before:h-full before:bg-linear-to-r before:from-blue_gradient before:via-body_bg before:to-yellow_gradient before:rounded-full before:top-24 before:blur-3xl before:-z-10'>
        <div className='container relative z-10'>
          <div className='flex flex-col gap-8'>
            {/* Heading */}
            <motion.div
              {...bottomAnimation}
              className='relative flex flex-col text-center items-center gap-4'>
              <h1 className='font-medium w-full'>
                {t('landing.hero.title')}
                <span className='instrument-font italic font-normal text-white/70'>
                  {t('landing.hero.titleHighlight')}
                </span>
              </h1>
              <p className='max-w-38 text-white/60'>
                {t('landing.hero.subtitle')}
              </p>
            </motion.div>

            {/* CTA + Social proof */}
            <motion.div
              {...bottomAnimation}
              className='flex flex-col items-center justify-center gap-4'>
              <div className='flex flex-col items-center justify-center gap-8 w-full sm:flex-row'>
                {/* Primary CTA */}
                <Link
                  href='/dashboard'
                  className='group overflow-hidden bg-accent text-white font-medium flex flex-row justify-between items-center py-2 px-5 rounded-full max-w-64 w-full md:py-3 border border-accent transition-all duration-200 ease-in-out hover:bg-transparent hover:text-accent'>
                  <span className='flex text-start transform transition-transform duration-200 ease-in-out group-hover:translate-x-28'>
                    {t('landing.hero.cta')}
                  </span>
                  <svg
                    width='40'
                    height='40'
                    viewBox='0 0 40 40'
                    fill='none'
                    xmlns='http://www.w3.org/2000/svg'
                    className='transform transition-transform duration-200 ease-in-out group-hover:-translate-x-44 group-hover:rotate-45'>
                    <rect width='40' height='40' rx='20' className='fill-white transition-colors duration-200 ease-in-out group-hover:fill-accent' />
                    <path d='M15.832 15.3334H24.1654V23.6667' className='stroke-[#1B1D1E] transition-colors duration-200 ease-in-out group-hover:stroke-white' strokeWidth='1.66667' strokeLinecap='round' strokeLinejoin='round' />
                    <path d='M15.832 23.6667L24.1654 15.3334' className='stroke-[#1B1D1E] transition-colors duration-500 ease-in-out group-hover:stroke-white' strokeWidth='1.66667' strokeLinecap='round' strokeLinejoin='round' />
                  </svg>
                </Link>

                {/* Tool badges */}
                <div className='flex items-center gap-3 flex-wrap justify-center'>
                  {['Semgrep', 'ESLint', 'Bandit', 'TruffleHog', 'npm audit', 'pip audit', 'Composer audit'].map((tool) => (
                    <span
                      key={tool}
                      className='inline-flex items-center gap-1.5 py-1 px-3 rounded-full bg-white/5 border border-white/10 text-sm text-white/70'>
                      <span className='w-1.5 h-1.5 rounded-full bg-accent' />
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}
