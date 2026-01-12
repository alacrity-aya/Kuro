/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        kuro: {
          bg: '#1a1b1e',
          panel: '#25262b',
          border: '#373a40',
          primary: '#4dabf7',
        }
      }
    },
  },
  plugins: [],
}
