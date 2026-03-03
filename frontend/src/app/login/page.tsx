'use client'
import Link from 'next/link'
import Image from 'next/image'
import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import toast, { Toaster } from 'react-hot-toast'
import SocialSignIn from '@/components/auth/SocialSignIn'
import { useTranslation } from '@/i18n'

/**
 * LoginPage — /login
 * -------------------
 * Page de connexion de l'utilisateur.
 *
 * Fonctionnement :
 * - Validation côté client (email + mot de passe)
 * - Envoi POST vers /api/auth/login/ (endpoint Django à implémenter dans apps/accounts)
 * - En cas de succès → redirection vers /dashboard
 * - En cas d'erreur → toast d'erreur
 *
 * TODO (backend) : créer l'endpoint POST /api/auth/login/ qui retourne
 * un token JWT ou une session selon l'implémentation choisie.
 */
export default function SignInPage() {
  const router = useRouter()
  const { t } = useTranslation()

  // État du formulaire
  const [loading, setLoading] = useState(false)
  const [form, setForm] = useState({ email: '', password: '' })

  // Erreurs de validation par champ
  const [errors, setErrors] = useState({ email: '', password: '' })

  // Callback OAuth : si ?code= est présent dans l'URL, échanger le code contre un JWT
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state') // 'github' ou 'google'
    if (!code) return

    const provider = state === 'google' ? 'google' : 'github'
    setLoading(true)
    // Nettoyer l'URL sans recharger la page
    window.history.replaceState({}, '', '/login')

    fetch(`/api/accounts/oauth/${provider}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ code, redirect_uri: `${window.location.origin}/login` }),
    })
      .then(res => {
        if (res.ok) {
          router.push('/dashboard')
        } else {
          toast.error(t('auth.login.errorOAuth'))
          setLoading(false)
        }
      })
      .catch(() => {
        toast.error(t('auth.login.errorOAuth'))
        setLoading(false)
      })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /**
   * validate — validation côté client avant envoi
   * Retourne true si le formulaire est valide, false sinon.
   * Met à jour l'état `errors` pour afficher les messages sous chaque champ.
   */
  const validate = () => {
    const e = { email: '', password: '' }
    if (!form.email) e.email = t('auth.login.errorEmailRequired')
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = t('auth.login.errorEmailInvalid')
    if (!form.password) e.password = t('auth.login.errorPasswordRequired')
    else if (form.password.length < 6) e.password = t('auth.login.errorPasswordMin')
    setErrors(e)
    return !e.email && !e.password
  }

  /**
   * handleSubmit — soumission du formulaire de connexion
   * Appelle l'API backend, redirige vers /dashboard en cas de succès.
   */
  const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault()

  if (!validate()) return

  setLoading(true)

  try {
    const res = await fetch('/api/accounts/login/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify(form)
    })

    if (!res.ok) throw new Error()

    router.push('/dashboard')

  } catch {
    toast.error(t('auth.login.errorInvalidCredentials'))
  } finally {
    setLoading(false)
  }
}

  return (
    <>
      <Toaster position='top-center' toastOptions={{ style: { background: '#0f1724', color: '#fff', border: '1px solid rgba(255,255,255,0.1)' } }} />
      <section className='min-h-screen flex items-center justify-center relative overflow-hidden bg-body_bg'>
        {/* Background glow */}
        <div className='absolute inset-0 -z-10'>
          <div className='absolute top-1/3 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-accent/10 rounded-full blur-3xl' />
          <div className='absolute top-1/4 left-1/4 w-[300px] h-[300px] bg-blue_gradient/30 rounded-full blur-3xl' />
        </div>

        <div className='w-full max-w-md px-4 py-16'>
          <div className='bg-card_bg border border-white/10 rounded-3xl px-8 py-12 text-center shadow-xl'>
            {/* Logo */}
            <div className='flex justify-center mb-10'>
              <Link href='/'>
                <Image src='/logo.png' alt='SecureScan' width={220} height={64} className='h-16 w-auto' />
              </Link>
            </div>

            <SocialSignIn />

            <div className='relative my-8'>
              <div className='absolute inset-0 flex items-center'>
                <div className='w-full border-t border-white/10' />
              </div>
              <div className='relative flex justify-center'>
                <span className='bg-card_bg px-3 text-sm text-white/40'>{t('auth.login.or')}</span>
              </div>
            </div>

            <form onSubmit={handleSubmit} className='flex flex-col gap-5 text-left'>
              <div>
                <input
                  type='email'
                  placeholder={t('auth.login.emailPlaceholder')}
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className={`w-full rounded-full border bg-white/5 px-5 py-3 text-white placeholder-white/30 outline-none transition focus:border-accent/50 ${errors.email ? 'border-red-500' : 'border-white/20'}`}
                />
                {errors.email && <p className='mt-1 text-sm text-red-400'>{errors.email}</p>}
              </div>
              <div>
                <input
                  type='password'
                  placeholder={t('auth.login.passwordPlaceholder')}
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className={`w-full rounded-full border bg-white/5 px-5 py-3 text-white placeholder-white/30 outline-none transition focus:border-accent/50 ${errors.password ? 'border-red-500' : 'border-white/20'}`}
                />
                {errors.password && <p className='mt-1 text-sm text-red-400'>{errors.password}</p>}
              </div>
              <button
                type='submit'
                disabled={loading}
                className='w-full rounded-full bg-accent py-3 font-medium text-white transition hover:bg-accent_dark disabled:opacity-60 cursor-pointer'>
                {loading ? t('auth.login.loading') : t('auth.login.submit')}
              </button>
            </form>

            <div className='mt-8 flex flex-col gap-2 text-sm text-white/50'>
              <Link href='/forgot-password' className='hover:text-white transition'>{t('auth.login.forgotPassword')}</Link>
              <p>
                {t('auth.login.noAccount')}{' '}
                <Link href='/signup' className='text-accent hover:text-accent_light transition'>{t('auth.login.createAccount')}</Link>
              </p>
            </div>
          </div>
        </div>
      </section>
    </>
  )
}
