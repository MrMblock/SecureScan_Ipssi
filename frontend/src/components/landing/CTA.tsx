'use client'
import Link from 'next/link'
import { motion } from 'motion/react'
import { useTranslation } from '@/i18n'

const bottomAnimation = {
  initial: { y: '5%', opacity: 0 },
  animate: { y: 0, opacity: 1 },
  transition: { duration: 1, delay: 0.8 },
}

export default function CTA() {
  const { t } = useTranslation()

  return (
    <section>
      <div className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='py-16 md:py-28 px-6 border border-white/10 rounded-3xl bg-[linear-gradient(90deg,#0a2540_0%,#060a13_33%,#060a13_66%,#1a1030_100%)] backdrop-blur-[200px]'>
            <motion.div
              {...bottomAnimation}
              className='flex flex-col gap-6 items-center md:max-w-3xl mx-auto'>
              <div className='flex flex-col gap-3 items-center text-center'>
                <h2 className='text-3xl md:text-5xl'>
                  {t('landing.cta.title')}{' '}
                  <span className='instrument-font italic font-normal text-white/70'>
                    {t('landing.cta.titleHighlight')}
                  </span>
                </h2>
                <p className='text-white/60'>
                  {t('landing.cta.subtitle')}
                </p>
              </div>
              <Link
                href='/dashboard'
                className='group overflow-hidden w-fit text-white font-medium bg-accent rounded-full flex items-center gap-4 py-2 pl-5 pr-2 hover:bg-transparent border border-accent transition-all duration-200 ease-in-out'>
                <span className='group-hover:translate-x-12 transform transition-transform duration-200 ease-in-out'>
                  {t('landing.cta.button')}
                </span>
                <svg
                  width='32'
                  height='32'
                  viewBox='0 0 32 32'
                  fill='none'
                  xmlns='http://www.w3.org/2000/svg'
                  className='group-hover:-translate-x-48 transition-all duration-200 ease-in-out group-hover:rotate-45'>
                  <rect
                    width='32'
                    height='32'
                    rx='16'
                    className='fill-white transition-colors duration-200 ease-in-out group-hover:fill-accent'
                  />
                  <path
                    d='M11.832 11.3334H20.1654M20.1654 11.3334V19.6668M20.1654 11.3334L11.832 19.6668'
                    className='stroke-[#1B1D1E] transition-colors duration-200 ease-in-out group-hover:stroke-white'
                    strokeWidth='1.42857'
                    strokeLinecap='round'
                    strokeLinejoin='round'
                  />
                </svg>
              </Link>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}
