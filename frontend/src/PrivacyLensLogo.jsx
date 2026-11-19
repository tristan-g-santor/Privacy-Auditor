import { useId } from 'react'

/**
 * PrivacyLens "Cutout P" mark: a solid P with an eye cut out of the bowl.
 * The cutout is a real mask, so it stays transparent on any background.
 * Pass tile="none" for the bare mark without the rounded square.
 */
export default function PrivacyLensLogo({
  size = 22,
  tile = '#5e6ad2',
  color = '#ffffff',
  className,
  title = 'PrivacyLens',
}) {
  // useId keeps the mask id unique if the logo appears more than once on a page.
  const maskId = `pl-cut-${useId().replace(/:/g, '')}`
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label={title} className={className}>
      <defs>
        <mask id={maskId}>
          <rect width="64" height="64" fill="#fff" />
          <path d="M21 28Q32 19 43 28Q32 37 21 28Z" fill="#000" />
        </mask>
      </defs>
      {tile !== 'none' && <rect width="64" height="64" rx="15" fill={tile} />}
      <g fill={color}>
        <path
          d="M18 14H33A14 14 0 0 1 33 42H28V50H18Z"
          stroke={color}
          strokeWidth={3}
          strokeLinejoin="round"
          mask={`url(#${maskId})`}
        />
        <circle cx="32" cy="28" r="3.8" />
      </g>
    </svg>
  )
}
