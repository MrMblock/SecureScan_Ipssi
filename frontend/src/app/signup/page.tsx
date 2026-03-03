'use client'
import Link from 'next/link'
import Image from 'next/image'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import toast, { Toaster } from 'react-hot-toast'
import SocialSignIn from '@/components/auth/SocialSignIn'
import { useTranslation } from '@/i18n'

/**
 * SignUpPage — /signup
 * ---------------------
 * Page d'inscription d'un nouvel utilisateur.
 *
 * Fonctionnement :
 * - Validation côté client (nom, email, mot de passe)
 * - Upload optionnel d'une photo de profil (prévisualisée localement)
 * - Envoi POST vers /api/auth/register/ (endpoint Django à implémenter dans apps/accounts)
 * - En cas de succès → toast de confirmation + redirection vers /dashboard
 *
 * TODO (backend) : créer l'endpoint POST /api/auth/register/ qui accepte
 * { name, email, password } et éventuellement un fichier avatar (multipart/form-data).
 */
export default function SignUpPage() {
  const router = useRouter()
  const { t } = useTranslation()

  // État du formulaire
  const [loading, setLoading] = useState(false)
  const [form, setForm] = useState({ name: '', email: '', password: '' })

  // Erreurs de validation par champ
  const [errors, setErrors] = useState({ name: '', email: '', password: '' })

  // Fichier avatar sélectionné + URL de prévisualisation locale
  const [avatar, setAvatar] = useState<File | null>(null)
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null)

  /**
   * handleAvatarChange — gestion de la sélection d'une image de profil
   * Génère une URL blob locale pour la prévisualisation sans upload immédiat.
   * L'upload réel se fait à la soumission du formulaire.
   */
  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setAvatar(file)
      setAvatarPreview(URL.createObjectURL(file))
    }
  }

  /**
   * validate — validation côté client avant envoi
   * Retourne true si tous les champs sont valides.
   * Met à jour l'état `errors` pour afficher les messages sous chaque champ.
   */
  const validate = () => {
    const e = { name: '', email: '', password: '' }
    if (!form.name.trim()) e.name = t('auth.signup.errorNameRequired')
    else if (form.name.trim().length < 3) e.name = t('auth.signup.errorNameMin')
    if (!form.email) e.email = t('auth.signup.errorEmailRequired')
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = t('auth.signup.errorEmailInvalid')
    if (!form.password) e.password = t('auth.signup.errorPasswordRequired')
    else if (form.password.length < 6) e.password = t('auth.signup.errorPasswordMin')
    setErrors(e)
    return !e.name && !e.email && !e.password
  }

  /**
   * handleChange — mise à jour générique des champs du formulaire
   * Utilise le `name` de l'input comme clé dans l'état `form`.
   */
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  /**
   * handleSubmit — soumission du formulaire d'inscription
   * TODO : si avatar présent, basculer en multipart/form-data pour envoyer le fichier.
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return
    setLoading(true)
    try {
      const body = new FormData()
      body.append('email', form.email)
      body.append('password', form.password)
      body.append('name', form.name)
      if (avatar) body.append('avatar', avatar)

      const res = await fetch('/api/accounts/signup/', {
        method: 'POST',
        credentials: 'include',
        body,
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || t('auth.signup.errorCreateAccount'))
      }
      toast.success(t('auth.signup.successMessage'))
      router.push('/dashboard')
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : t('auth.signup.errorDefault'))
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
          <div className='absolute top-1/4 right-1/4 w-[300px] h-[300px] bg-yellow_gradient/30 rounded-full blur-3xl' />
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
                <span className='bg-card_bg px-3 text-sm text-white/40'>{t('auth.signup.or')}</span>
              </div>
            </div>

            <form onSubmit={handleSubmit} className='flex flex-col gap-5 text-left'>
              {/* Photo de profil */}
              <div className='flex flex-col items-center gap-3'>
                <label htmlFor='avatar' className='cursor-pointer group relative'>
                  <div className='w-20 h-20 rounded-full border-2 border-dashed border-white/20 bg-white/5 flex items-center justify-center overflow-hidden group-hover:border-accent/50 transition'>
                    {avatarPreview
                      ? <img src={avatarPreview} alt='avatar' className='w-full h-full object-cover' />
                      : <span className="material-symbols-outlined text-3xl text-white/30 transition group-hover:text-accent/60">add_a_photo</span>
                    }
                  </div>
                </label>
                <input id='avatar' type='file' accept='image/*' onChange={handleAvatarChange} className='hidden' />
                <span className='text-xs text-white/30'>{t('auth.signup.avatarLabel')}</span>
              </div>
              <div>
                <input
                  type='text'
                  name='name'
                  placeholder={t('auth.signup.namePlaceholder')}
                  value={form.name}
                  onChange={handleChange}
                  className={`w-full rounded-full border bg-white/5 px-5 py-3 text-white placeholder-white/30 outline-none transition focus:border-accent/50 ${errors.name ? 'border-red-500' : 'border-white/20'}`}
                />
                {errors.name && <p className='mt-1 text-sm text-red-400'>{errors.name}</p>}
              </div>
              <div>
                <input
                  type='email'
                  name='email'
                  placeholder={t('auth.signup.emailPlaceholder')}
                  value={form.email}
                  onChange={handleChange}
                  className={`w-full rounded-full border bg-white/5 px-5 py-3 text-white placeholder-white/30 outline-none transition focus:border-accent/50 ${errors.email ? 'border-red-500' : 'border-white/20'}`}
                />
                {errors.email && <p className='mt-1 text-sm text-red-400'>{errors.email}</p>}
              </div>
              <div>
                <input
                  type='password'
                  name='password'
                  placeholder={t('auth.signup.passwordPlaceholder')}
                  value={form.password}
                  onChange={handleChange}
                  className={`w-full rounded-full border bg-white/5 px-5 py-3 text-white placeholder-white/30 outline-none transition focus:border-accent/50 ${errors.password ? 'border-red-500' : 'border-white/20'}`}
                />
                {errors.password && <p className='mt-1 text-sm text-red-400'>{errors.password}</p>}
              </div>
              <button
                type='submit'
                disabled={loading}
                className='w-full rounded-full bg-accent py-3 font-medium text-white transition hover:bg-accent_dark disabled:opacity-60 cursor-pointer'>
                {loading ? t('auth.signup.loading') : t('auth.signup.submit')}
              </button>
            </form>

            <div className='mt-8 text-sm text-white/50'>
              <p>
                {t('auth.signup.alreadyHaveAccount')}{' '}
                <Link href='/login' className='text-accent hover:text-accent_light transition'>{t('auth.signup.login')}</Link>
              </p>
            </div>
          </div>
        </div>
      </section>
    </>
  )
}
