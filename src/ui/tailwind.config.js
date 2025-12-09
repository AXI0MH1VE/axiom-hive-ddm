// AxiomHive Visual Theme OS v2.1.0
// Tailwind CSS Configuration
// Zero Entropy Law: C=0 enforced

module.exports = {
  content: [
    "./src/**/*.{html,js,jsx,ts,tsx}",
    "./public/**/*.html"
  ],
  theme: {
    extend: {
      colors: {
        'axiom-black': '#000000',
        'miami-red': '#FF0038',
      },
      fontFamily: {
        'mono': ['Courier New', 'monospace'],
      },
      backgroundImage: {
        'hex-grid': 'radial-gradient(circle at 25% 25%, var(--miami-red) 1px, transparent 1px), radial-gradient(circle at 75% 75%, var(--miami-red) 1px, transparent 1px)',
      },
      backgroundSize: {
        'hex': '24px 24px',
      },
    },
  },
  plugins: [],
}
