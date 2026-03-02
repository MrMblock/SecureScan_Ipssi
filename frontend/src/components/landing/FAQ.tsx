'use client'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@radix-ui/react-accordion'
import { motion } from 'motion/react'
import { useTranslation } from '@/i18n'
import fr from '@/i18n/locales/fr.json'
import en from '@/i18n/locales/en.json'

const bottomAnimation = {
  initial: { y: '20%', opacity: 0 },
  animate: { y: 0, opacity: 1 },
  transition: { duration: 1, delay: 0.8 },
}

export default function FAQ() {
  const { t, locale } = useTranslation()

  const translations = locale === 'en' ? en : fr
  const faqs = translations.landing.faq.items

  return (
    <section id='faq'>
      <div className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='flex flex-col gap-10 md:gap-20'>
            <div className='max-w-md text-center mx-auto'>
              <h2>
                {t('landing.faq.title')}{' '}
                <span className='instrument-font italic font-normal text-white/70'>
                  {t('landing.faq.titleHighlight')}
                </span>
              </h2>
            </div>
            <motion.div {...bottomAnimation} className='flex flex-col'>
              <Accordion
                type='single'
                collapsible
                className='flex flex-col gap-4'>
                {faqs.map((item, index) => (
                  <AccordionItem
                    key={index}
                    value={`item-${index}`}
                    className='p-6 border border-white/10 rounded-xl group data-[state=open]:border-white/20 transition-all'>
                    <AccordionTrigger className='flex items-center justify-between w-full text-left cursor-pointer'>
                      <h5 className='text-white/80 pr-4'>
                        {item.q}
                      </h5>
                      <svg
                        width='20'
                        height='20'
                        viewBox='0 0 24 24'
                        fill='none'
                        stroke='currentColor'
                        strokeWidth='2'
                        strokeLinecap='round'
                        strokeLinejoin='round'
                        className='shrink-0 text-white/40 transition-transform duration-200 group-data-[state=open]:rotate-180'>
                        <polyline points='6 9 12 15 18 9' />
                      </svg>
                    </AccordionTrigger>
                    <AccordionContent className='overflow-hidden data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down'>
                      <p className='text-base font-normal text-white/60 pt-4'>
                        {item.a}
                      </p>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}
