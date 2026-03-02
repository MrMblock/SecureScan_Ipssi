'use client'
import CountUp from 'react-countup'
import { useInView } from 'react-intersection-observer'
import { useTranslation } from '@/i18n'

export default function Stats() {
  const { t } = useTranslation()
  const { ref, inView } = useInView({
    triggerOnce: true,
    threshold: 0.5,
  })

  return (
    <section>
      <div className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='flex flex-col lg:gap-16 gap-5'>
            <div className='flex flex-col items-center justify-center text-center gap-3'>
              <h2 className='max-w-6xl'>
                {t('landing.stats.title')}{' '}
                <span className='instrument-font italic font-normal text-white/70'>
                  {t('landing.stats.titleHighlight')}
                </span>
              </h2>
            </div>
            <div className='flex-col md:flex md:flex-row justify-center items-center text-center'>
              <div className='relative 2xl:px-24 px-16 md:py-8 py-4'>
                <h2 ref={ref} className='2xl:text-9xl md:text-7xl text-5xl'>
                  {inView ? <CountUp start={0} end={10} duration={3} /> : '0'}
                </h2>
                <p className='mt-2 text-white/60'>
                  {t('landing.stats.owaspCategories')}
                </p>
                <div className='hidden md:block absolute right-0 top-1/2 transform -translate-y-1/2 h-28 w-px bg-white/10' />
              </div>
              <div className='relative 2xl:px-24 px-16 md:py-8 py-4'>
                <h2 className='2xl:text-9xl md:text-7xl text-5xl'>
                  {inView ? <CountUp start={0} end={7} duration={3} /> : '0'}
                </h2>
                <p className='mt-2 text-white/60'>
                  {t('landing.stats.analyzers')}
                </p>
                <div className='hidden md:block absolute right-0 top-1/2 transform -translate-y-1/2 h-28 w-px bg-white/10' />
              </div>
              <div className='relative 2xl:px-24 px-16 md:py-8 py-4'>
                <h2 className='2xl:text-9xl md:text-7xl text-5xl'>
                  <sup>+</sup>
                  {inView ? <CountUp start={0} end={15} duration={3} /> : '0'}
                </h2>
                <p className='mt-2 text-white/60'>
                  {t('landing.stats.autoFixPatterns')}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
