import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#040810',
          900: '#060b14',
          850: '#0a1120',
          800: '#0d1526',
          700: '#131e33',
          600: '#1b2a45',
        },
        line: {
          faint: '#101a2c',
          soft: '#1a2740',
          strong: '#24324f',
        },
        cyan: {
          glow: '#38bdf8',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
export default config
