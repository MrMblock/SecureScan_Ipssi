'use client'
import Image from 'next/image'
import Slider from 'react-infinite-logo-slider'

const slides = Array(8).fill(null)

export default function TrustedTools() {
  return (
    <section>
      <div className='2xl:py-20 py-11'>
        <div className='container'>
          <div className='gap-4'>
            <div className='flex justify-center text-center py-4 relative'>
              <p
                className='relative px-2 text-white/60
                    md:before:absolute md:before:right-[-150px] md:before:top-1/2 md:before:h-0.5 md:before:w-36 md:before:bg-linear-to-r md:before:from-gray-300 md:before:opacity-100 md:before:to-transparent md:after:absolute md:after:left-[-150px] md:after:top-1/2 md:after:h-0.5 md:after:w-36 md:after:bg-linear-to-l md:after:from-gray-300 md:after:opacity-100 md:after:to-transparent'>
                Hackathon IPSSI
              </p>
            </div>

            <div className='py-3 Xsm:py-7'>
              <Slider
                width='220px'
                duration={20}
                pauseOnHover={true}
                blurBorders={false}>
                {slides.map((_, index) => (
                  <Slider.Slide key={index}>
                    <div className='flex items-center justify-center px-8'>
                      <Image
                        src='/image.png'
                        alt='IPSSI'
                        width={100}
                        height={40}
                        className='h-8 w-auto object-contain brightness-0 invert opacity-60'
                      />
                    </div>
                  </Slider.Slide>
                ))}
              </Slider>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
