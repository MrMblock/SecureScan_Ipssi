'use client'
import { useState, useRef } from 'react'
import { motion, useInView } from 'motion/react'

const vulnerableCode = [
  { num: 41, text: '  const userInput = req.body.username;', cls: '' },
  { num: 42, text: '  const query = "SELECT * FROM users WHERE user = \'" + userInput + "\'";', cls: 'code-removed' },
  { num: 43, text: '  db.execute(query);', cls: 'code-removed' },
  { num: 44, text: '', cls: '' },
  { num: 45, text: '  return result;', cls: '' },
]

const fixedCode = [
  { num: 41, text: '  const userInput = req.body.username;', cls: '' },
  { num: 42, text: '  const query = "SELECT * FROM users WHERE user = ?";', cls: 'code-added' },
  { num: 43, text: '  db.execute(query, [userInput]);', cls: 'code-added' },
  { num: 44, text: '  // Parameterized query prevents SQLi', cls: 'code-added' },
  { num: 45, text: '  return result;', cls: '' },
]

export default function CodePreview() {
  const [showFixed, setShowFixed] = useState(false)
  const ref = useRef(null)
  const inView = useInView(ref)

  const bottomAnimation = {
    initial: { y: '15%', opacity: 0 },
    animate: inView ? { y: 0, opacity: 1 } : { y: '15%', opacity: 0 },
    transition: { duration: 0.5, delay: 0.3 },
  }

  return (
    <section>
      <div ref={ref} className='2xl:py-20 py-11'>
        <div className='container'>
          <motion.div
            {...bottomAnimation}
            className='grid grid-cols-1 lg:grid-cols-2 gap-12 items-center'>
            {/* Left — text */}
            <div className='flex flex-col gap-4'>
              <div className='flex flex-wrap gap-2'>
                <span className='inline-flex items-center gap-1.5 py-1 px-3 rounded-full bg-severity_critical/10 border border-severity_critical/20 text-severity_critical text-xs font-medium'>
                  CRITICAL
                </span>
                <span className='inline-flex items-center gap-1.5 py-1 px-3 rounded-full bg-white/5 border border-white/10 text-white/70 text-xs font-medium'>
                  OWASP A05:2025 — Injection
                </span>
              </div>

              <h2 className='mt-2'>
                SQL Injection{' '}
                <span className='instrument-font italic font-normal text-white/70'>
                  Remediation
                </span>
              </h2>

              <p className='text-white/60 leading-relaxed'>
                Detecte par <span className='text-white font-medium'>Semgrep</span> dans{' '}
                <code className='text-accent text-sm bg-white/5 px-1.5 py-0.5 rounded font-mono'>
                  src/auth/login.ts
                </code>
                . L&apos;IA suggere de remplacer la concatenation brute par des requetes parametrees.
              </p>

              {/* AI Analysis card */}
              <div className='bg-white/5 border border-white/10 rounded-2xl p-5'>
                <div className='flex items-center gap-2 mb-3'>
                  <svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#8b5cf6' strokeWidth='2' strokeLinecap='round' strokeLinejoin='round'>
                    <path d='M12 2a4 4 0 0 0-4 4c0 2 2 3 2 6H8a2 2 0 1 0 0 4h8a2 2 0 1 0 0-4h-2c0-3 2-4 2-6a4 4 0 0 0-4-4z' />
                  </svg>
                  <span className='text-white font-medium text-sm'>AI Analysis</span>
                </div>
                <p className='text-white/60 text-sm leading-relaxed'>
                  Le code original construit une requete SQL en concatenant directement
                  l&apos;input utilisateur. Un attaquant peut manipuler la logique de la requete
                  (ex: <code className='text-white/80 font-mono text-xs'>&apos; OR &apos;1&apos;=&apos;1</code>).
                </p>
                <div className='mt-3 flex items-center gap-3 text-xs'>
                  <span className='text-success'>Confiance : 98%</span>
                  <span className='text-white/20'>|</span>
                  <span className='text-white/40'>Effort : 5 min</span>
                </div>
              </div>

              <button
                onClick={() => setShowFixed(!showFixed)}
                className='w-fit bg-accent text-white px-6 py-2.5 rounded-full text-sm font-medium transition-all hover:bg-accent_dark flex items-center gap-2'>
                <svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' strokeWidth='2' strokeLinecap='round' strokeLinejoin='round'>
                  <path d='M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z' />
                </svg>
                {showFixed ? 'Voir le code vulnerable' : 'Appliquer le fix'}
              </button>
            </div>

            {/* Right — code diff */}
            <div className='bg-card_bg border border-white/10 rounded-2xl overflow-hidden'>
              {/* Tab bar */}
              <div className='flex items-center gap-4 px-4 py-3 border-b border-white/10 text-xs'>
                <button
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-full transition-colors ${
                    !showFixed
                      ? 'bg-severity_critical/10 text-severity_critical'
                      : 'text-white/40 hover:text-white/60'
                  }`}
                  onClick={() => setShowFixed(false)}>
                  <span className='w-2 h-2 rounded-full bg-severity_critical' />
                  Original
                </button>
                <button
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-full transition-colors ${
                    showFixed
                      ? 'bg-success/10 text-success'
                      : 'text-white/40 hover:text-white/60'
                  }`}
                  onClick={() => setShowFixed(true)}>
                  <span className='w-2 h-2 rounded-full bg-success' />
                  Suggested Fix
                </button>
              </div>

              {/* Code block */}
              <div className='p-4 font-mono text-sm overflow-x-auto'>
                {(showFixed ? fixedCode : vulnerableCode).map((line) => (
                  <div key={line.num} className={`flex ${line.cls} rounded px-2 py-0.5`}>
                    <span className='text-white/20 w-8 shrink-0 select-none text-right mr-4'>
                      {line.num}
                    </span>
                    <span className='text-white/80 whitespace-pre'>{line.text}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
