// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'null Web Security Study Group',
  tagline: 'Resources & Study Materials for Learning Web Security!',
  url: 'https://blog.null.community',
  baseUrl: '/study-group-web-security/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',
  organizationName: 'null-open-security-community', // Usually your GitHub org/user name.
  projectName: 'study-group-web-security', // Usually your repo name.
  deploymentBranch: 'main',

  presets: [
    [
      '@docusaurus/preset-classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: 'docs',
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          editUrl: 'https://github.com/null-open-security-community/study-group-web-security',
          // showLastUpdateAuthor: true,
          showLastUpdateTime: true,
        },
        
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'null Web Security Study Group',
        items: [
          {
            type: 'doc',
            docId: 'intro',
            position: 'left',
            label: 'Documentation',
          },
          // {to: '/blog', label: 'Blog', position: 'left'},
          {to: 'showcase', label: 'Showcase', position: 'left'},
          {
            href: 'https://www.linkedin.com/company/null-the-open-security-community',
            className: 'header-github-link',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Documentation',
                to: '/docs/intro',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'Twitter',
                href: 'https://twitter.com/null0x00',
              },
              {
                label: 'Discord',
                href: 'https://discord.gg/bhwDVGC9Du',
              },
              {
                label: 'LinkedIn',
                href: 'https://www.linkedin.com/company/null-the-open-security-community',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Website',
                href: 'https://null.community',
              },
              {
                label: 'GitHub',
                href: 'https://github.com/null-open-security-community',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} null Web Security Study Group. Built with Docusaurus.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;

// Good Day!