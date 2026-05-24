/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: '#0a0a0a',
          dark: '#1a1a1a',
          gray: '#2a2a2a',
          light: '#3a3a3a',
          accent: '#4a4a4a',
          blue: '#00d4ff',
          green: '#00ff88',
          orange: '#ff6b00',
          red: '#ff004d',
          purple: '#8b5cf6',
        },
        robot: {
          primary: '#2d3748',
          secondary: '#4a5568',
          accent: '#00d4ff',
          highlight: '#00ff88',
          warning: '#ffd60a',
          danger: '#ff073a',
        }
      },
      backgroundImage: {
        'circuit': "url('data:image/svg+xml;utf8,<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\" viewBox=\"0 0 100 100\"><defs><pattern id=\"circuit\" patternUnits=\"userSpaceOnUse\" width=\"100\" height=\"100\"><path d=\"M20,20 L80,20 L80,80 L20,80 Z\" fill=\"none\" stroke=\"%23ffffff\" stroke-width=\"0.5\" opacity=\"0.1\"/><circle cx=\"20\" cy=\"20\" r=\"2\" fill=\"%2300d4ff\" opacity=\"0.3\"/><circle cx=\"80\" cy=\"20\" r=\"2\" fill=\"%2300d4ff\" opacity=\"0.3\"/><circle cx=\"80\" cy=\"80\" r=\"2\" fill=\"%2300d4ff\" opacity=\"0.3\"/><circle cx=\"20\" cy=\"80\" r=\"2\" fill=\"%2300d4ff\" opacity=\"0.3\"/></pattern></defs><rect width=\"100\" height=\"100\" fill=\"url(%23circuit)\"/></svg>')",
      },
      animation: {
        'glow': 'glow 2s ease-in-out infinite alternate',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px theme(colors.cyber.blue)' },
          '100%': { boxShadow: '0 0 20px theme(colors.cyber.blue), 0 0 30px theme(colors.cyber.blue)' }
        },
        scan: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' }
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Monaco', 'monospace'],
        'cyber': ['Orbitron', 'Exo 2', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
