/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          900: '#0f172a', // Slate 900
          800: '#1e293b', // Slate 800
          700: '#334155', // Slate 700
          600: '#475569', // Slate 600
          500: '#64748b', // Slate 500
          400: '#94a3b8', // Slate 400
          300: '#cbd5e1', // Slate 300
          200: '#e2e8f0', // Slate 200
          100: '#f1f5f9', // Slate 100
          50: '#f8fafc',  // Slate 50
          primary: '#4f46e5', // Indigo 600
          secondary: '#0ea5e9', // Sky 500
          accent: '#8b5cf6', // Violet 500
          success: '#10b981', // Emerald 500
          warning: '#f59e0b', // Amber 500
          danger: '#ef4444', // Red 500
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
