import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'DeepSight',
  description: 'Real-time system monitoring & security dashboard',
  base: '/docs/',
  outDir: '../static/docs',
  
  themeConfig: {
    nav: [
      { text: 'Dashboard', link: 'https://open-claw01.tail9058f7.ts.net:8451/' },
      { text: 'GitHub', link: 'https://github.com/R3dy/myclaw' },
    ],
    sidebar: [
      {
        text: 'DeepSight',
        collapsed: false,
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Getting Started', link: '/getting-started' },
        ],
      },
      {
        text: 'Guide',
        collapsed: false,
        items: [
          { text: 'Dashboard UI', link: '/dashboard' },
          { text: 'Security Monitoring', link: '/security' },
          { text: 'Remote Agents', link: '/agents' },
        ],
      },
      {
        text: 'Reference',
        collapsed: false,
        items: [
          { text: 'API Reference', link: '/api' },
          { text: 'Architecture', link: '/architecture' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/R3dy/myclaw' },
    ],
    search: {
      provider: 'local',
    },
    footer: {
      message: 'Built with VitePress · DeepSight System Dashboard',
    },
    outline: 'deep',
  },
  
  markdown: {
    theme: 'one-dark-pro',
    lineNumbers: true,
  },
})
