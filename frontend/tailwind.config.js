/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          950: "#050811",
          900: "#070b14",
          850: "#0b1220",
          800: "#0f172a",
          700: "#1e293b",
          600: "#334155",
        },
        brand: {
          cyan: "#06b6d4",
          blue: "#3b82f6",
          purple: "#8b5cf6",
        }
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
};
