/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Global Theme (Root Colors)
        'bg-primary': '#0A0F1C',
        'bg-secondary': '#0E1624',
        'bg-card': '#121B2E',
        'bg-sidebar': '#0C1422',
        'bg-panel': '#101A2C',
        'border-divider': '#2A3450',
        'scrollbar-track': '#0E1624',
        'scrollbar-thumb': '#1A253B',
        
        // Primary Accent Colors (Neon Cyber Blue)
        'accent-primary': '#00E5FF',
        'accent-hover': '#14B8FF',
        'accent-deep': '#0078F0',
        'accent-glow': '#33FFFF',
        
        // Secondary Accent Colors (Neon Purple)
        'accent-secondary': '#A855F7',
        'accent-secondary-deep': '#7C3AED',
        'accent-secondary-glow': '#C084FC',
        
        // AI Highlight Colors (Cyan + Teal)
        'ai-cyan': '#4FE3C1',
        'aqua-light': '#21F6F6',
        'teal-deep': '#0D9488',
        
        // Text Colors
        'text-primary': '#E4ECFF',
        'text-secondary': '#C7D2FE',
        'text-muted': '#94A3B8',
        'text-disabled': '#64748B',
        'text-highlight': '#00E5FF',
        
        // Button Colors
        'btn-primary': '#0078F0',
        'btn-primary-hover': '#00A6FF',
        'btn-outline-border': '#00E5FF',
        'btn-outline-hover': '#14B8FF',
        'btn-secondary': '#7C3AED',
        'btn-secondary-hover': '#A855F7',
        
        // Input + Form Colors
        'input-bg': '#0D1525',
        'input-border': '#25304A',
        'input-focus': '#00E5FF',
        'input-placeholder': '#6B7280',
        
        // Navbar / Header Colors
        'navbar-bg': '#0C1422',
        'navbar-border': '#1A253B',
        'navbar-active': '#00E5FF',
        'navbar-hover': '#14B8FF',
        
        // Sidebar Colors
        'sidebar-bg': '#0C1422',
        'sidebar-active': '#121F36',
        'sidebar-active-border': '#00E5FF',
        'sidebar-text': '#C7D2FE',
        
        // Card + Panel Colors
        'card-bg': '#121B2E',
        'card-border': '#25304A',
        'panel-bg': '#101A2C',
        
        // Table Colors
        'table-header-bg': '#101A2C',
        'table-header-text': '#E4ECFF',
        'table-row-bg': '#0E1624',
        'table-row-hover': '#121F34',
        'table-border': '#25304A',
        
        // Detection / Severity Colors
        'severity-critical': '#FF0033',
        'severity-high': '#FF1744',
        'severity-medium': '#FFB300',
        'severity-low': '#4CAF50',
        'severity-benign': '#00C853',
        
        // Chart Colors
        'chart-primary': '#00E5FF',
        'chart-secondary': '#A855F7',
        'chart-warning': '#FF1744',
        'chart-grid': '#25304A',
        
        // Toast / Notification Colors
        'toast-success-bg': '#0D2820',
        'toast-success-border': '#00C853',
        'toast-error-bg': '#2B0F14',
        'toast-error-border': '#FF1744',
        'toast-warning-bg': '#2A1A06',
        'toast-warning-border': '#FFB300',
        'toast-info-bg': '#0A1D2B',
        'toast-info-border': '#00E5FF',
      },
      boxShadow: {
        'neon-blue': '0 0 12px #00E5FF',
        'purple-glow': '0 0 10px #A855F7',
        'aqua-glow': '0 0 15px #21F6F6',
        'red-glow': '0 0 12px #FF0033',
        'soft-ambient': '0 0 25px rgba(0,255,255,0.15)',
        'card-glow': '0 0 10px rgba(0, 229, 255, 0.25)',
      },
      backgroundImage: {
        'gradient-blue': 'linear-gradient(to right, #00E5FF, #0078F0)',
        'gradient-purple': 'linear-gradient(to right, #A855F7, #7C3AED)',
        'gradient-teal': 'linear-gradient(to right, #21F6F6, #0D9488)',
        'gradient-red': 'linear-gradient(to right, #FF1744, #FF0033)',
      },
    },
  },
  plugins: [],
}