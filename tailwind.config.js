/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          900: '#05050a', // Darker background
          800: '#0f1016', // Card background
          700: '#1a1b26', // Border/Input
          accent: '#00f2ff', // Neon Cyan
          primary: '#7000ff', // Neon Purple
          danger: '#ff003c', // Neon Red
          success: '#00ff9d', // Neon Green
          text: '#e0e0e0',
          muted: '#808090',
        },
      },
      fontFamily: {
        mono: ['"Fira Code"', 'monospace'], // Good for code/security vibes
        sans: ['Inter', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
    },
  },
  plugins: [],
}
