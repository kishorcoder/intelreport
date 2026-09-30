import { motion, useReducedMotion } from 'motion/react';

// Full shield outline (lucide "shield" geometry), drawn as a faint track.
const SHIELD_PATH =
  'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1' +
  'c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z';

// The route the light streak travels: one full clockwise lap starting and ending at the
// top-centre point of the shield (the peak of the top notch, (12, 2)).
const SCAN_ROUTE =
  'M12 2A1.17 1.17 0 0 1 12.76 2.28C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1V13' +
  'c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1' +
  'c2 0 4.5-1.2 6.24-2.72A1.17 1.17 0 0 1 12 2';

// Streak lengths below were tuned on a route 43.2 units long; this lap is 58.7, so
// scale them down to keep the same on-screen streak length.
const ROUTE_SCALE = 43.2 / 58.7;

const RED = '#ee1b24';
const RED_SOFT = '#ff5a5f';
const SCAN_EASE = [0.45, 0, 0.55, 1] as const;
const SCAN_DURATION = 2 / ROUTE_SCALE; // same travel speed as before on the longer lap

const SIZE = 254; // px
// Shield border width in the 24-unit viewBox; scaled down with SIZE so the line stays
// the same on-screen thickness (about 2px) however large the shield is drawn.
const STROKE = 0.32 * (150 / SIZE);
const GLOW_BLUR = 0.55 * (150 / SIZE);

// How much thicker than the border the streak gets at its white-hot centre; it tapers
// back to border width at the tips.
const STREAK_THICKNESS = 2.2;

// Stacked segments centred on the same moving point: a blurred glow, then many thin
// translucent red segments of shrinking length (their overlap builds a smooth fade
// toward the centre, and their growing width a taper), topped by a short white-hot
// core — the same falloff as the progress-line streak. Lengths are fractions of the
// route.
const TAIL_STEPS = 12;
const STREAK_LAYERS = [
  { len: 0.22, color: RED, width: STROKE * STREAK_THICKNESS * 2, opacity: 0.4, blur: true },
  ...Array.from({ length: TAIL_STEPS }, (_, i) => ({
    len: 0.025 + 0.33 * (1 - i / TAIL_STEPS) ** 1.4,
    color: i < TAIL_STEPS * 0.6 ? RED : RED_SOFT,
    width: STROKE * (1 + (STREAK_THICKNESS - 1) * (i / (TAIL_STEPS - 1))),
    opacity: 0.2,
    blur: false,
  })),
  { len: 0.045, color: '#ffc2c4', width: STROKE * STREAK_THICKNESS, opacity: 0.9, blur: false },
  { len: 0.018, color: '#ffffff', width: STROKE * STREAK_THICKNESS, opacity: 1, blur: false },
].map((layer) => ({ ...layer, len: layer.len * ROUTE_SCALE }));

// Head travels from just before the route's start to just past its end, so the
// streak grows out of the top centre and slides back into it at the end of the lap.
const HEAD_FROM = -0.13 * ROUTE_SCALE;
const HEAD_TO = 1 + 0.13 * ROUTE_SCALE;

export function ShieldLoader({
  label = 'Querying live sources...',
  cyberLabel = false,
}: {
  label?: string;
  /** Neon red label, matching the streak — used for the idle "ready" state */
  cyberLabel?: boolean;
}) {
  const reduce = useReducedMotion();
  const scan = { duration: SCAN_DURATION, ease: SCAN_EASE, repeat: Infinity, repeatDelay: 0.15 };

  return (
    <div
      role="status"
      aria-label={label}
      // On the lookup page this block starts ~100px down (under the search bar); the
      // 200px trim centres the shield on the screen, matching the opening screen.
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 22, minHeight: 'calc(100vh - 200px)' }}
    >
      <div style={{ position: 'relative', width: SIZE, height: SIZE }}>
        <svg viewBox="0 0 24 24" width={SIZE} height={SIZE} fill="none" style={{ overflow: 'visible' }}>
          <defs>
            <filter id="streak-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation={GLOW_BLUR} />
            </filter>
          </defs>

          {/* Faint track so the whole shield reads even where the streak isn't */}
          <path d={SHIELD_PATH} stroke="rgba(56,189,248,0.35)" strokeWidth={STROKE} strokeLinejoin="round" />

          {!reduce &&
            STREAK_LAYERS.map((layer) => (
              <motion.path
                key={`${layer.len}-${layer.width}`}
                d={SCAN_ROUTE}
                stroke={layer.color}
                strokeWidth={layer.width}
                strokeLinecap={layer.blur ? 'round' : 'butt'}
                strokeLinejoin="round"
                opacity={layer.opacity}
                filter={layer.blur ? 'url(#streak-glow)' : undefined}
                initial={{ pathLength: layer.len, pathSpacing: 3, pathOffset: HEAD_FROM - layer.len / 2 }}
                animate={{ pathOffset: HEAD_TO - layer.len / 2 }}
                transition={scan}
              />
            ))}
        </svg>
      </div>

      <div
        style={{
          fontSize: 13,
          letterSpacing: '0.02em',
          ...(cyberLabel
            ? { color: RED_SOFT, fontWeight: 500, textShadow: '0 0 10px rgba(238,27,36,0.6)' }
            : { color: 'var(--text-mid)' }),
        }}
      >
        {label}
      </div>
    </div>
  );
}
