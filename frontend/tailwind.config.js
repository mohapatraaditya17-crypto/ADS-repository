/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0D1117",
        cardBg: "#161B22",
        accentBlue: "#1F6FEB",
        borderDark: "#30363D",
        textMain: "#C9D1D9",
        textMuted: "#8B949E",
        severity: {
          critical: "#FF7B72",
          high: "#FFA657",
          medium: "#D29922",
          low: "#58A6FF",
          info: "#79C0FF",
        }
      },
    },
  },
  plugins: [],
}
