import { defineConfig } from 'vitepress';
import { GITHUB_REPO as repository } from '../../src/constants.js';

const zhSidebar = [
    {
        text: '开始使用',
        items: [
            { text: '项目概览', link: '/guide/getting-started' },
            { text: '部署方式', link: '/guide/deployment' },
            { text: '环境配置', link: '/guide/configuration' }
        ]
    },
    {
        text: '转换与兼容性',
        items: [
            { text: '接口说明', link: '/guide/api' },
            { text: '协议支持矩阵', link: '/protocol-support' },
            { text: '常见问题', link: '/guide/faq' }
        ]
    }
];

const enSidebar = [
    {
        text: 'Getting Started',
        items: [
            { text: 'Overview', link: '/en/guide/getting-started' },
            { text: 'Deployment', link: '/en/guide/deployment' },
            { text: 'Configuration', link: '/en/guide/configuration' }
        ]
    },
    {
        text: 'Conversion',
        items: [
            { text: 'HTTP Endpoints', link: '/en/guide/api' },
            { text: 'Protocol Support', link: '/en/protocol-support' },
            { text: 'FAQ', link: '/en/guide/faq' }
        ]
    }
];

export default defineConfig({
    title: 'Sublink Worker',
    description: '多平台代理订阅转换与管理工具',
    lang: 'zh-CN',
    base: '/sublink-worker/',
    cleanUrls: true,
    srcExclude: ['research/**'],
    lastUpdated: true,
    sitemap: {
        hostname: 'https://eicky.github.io/sublink-worker/'
    },
    head: [
        ['link', { rel: 'icon', type: 'image/svg+xml', href: '/sublink-worker/logo.svg' }],
        ['link', { rel: 'alternate icon', type: 'image/x-icon', href: '/sublink-worker/favicon.ico' }],
        ['link', { rel: 'apple-touch-icon', sizes: '512x512', href: '/sublink-worker/favicon.png' }],
        ['meta', { name: 'theme-color', content: '#1d4ed8' }],
        ['meta', { property: 'og:type', content: 'website' }],
        ['meta', { property: 'og:title', content: 'Sublink Worker' }],
        ['meta', { property: 'og:description', content: '多平台代理订阅转换与管理工具' }]
    ],
    locales: {
        root: {
            label: '简体中文',
            lang: 'zh-CN',
            title: 'Sublink Worker',
            description: '多平台代理订阅转换与管理工具'
        },
        en: {
            label: 'English',
            lang: 'en-US',
            link: '/en/',
            title: 'Sublink Worker',
            description: 'A multi-platform proxy subscription converter and manager'
        }
    },
    markdown: {
        lineNumbers: true
    },
    themeConfig: {
        logo: '/logo.svg',
        siteTitle: 'Sublink Worker',
        search: {
            provider: 'local'
        },
        socialLinks: [
            { icon: 'github', link: repository }
        ],
        nav: [
            { text: '指南', link: '/guide/getting-started' },
            { text: '协议支持', link: '/protocol-support' },
            { text: '发布版本', link: `${repository}/releases` },
            { text: 'GitHub', link: repository }
        ],
        sidebar: zhSidebar,
        outline: { label: '本页内容', level: [2, 3] },
        docFooter: { prev: '上一篇', next: '下一篇' },
        lastUpdated: { text: '最后更新于' },
        editLink: {
            pattern: `${repository}/edit/main/docs/:path`,
            text: '在 GitHub 上编辑此页'
        },
        returnToTopLabel: '返回顶部',
        sidebarMenuLabel: '菜单',
        langMenuLabel: '切换语言',
        skipToContentLabel: '跳转到正文',
        darkModeSwitchLabel: '外观',
        lightModeSwitchTitle: '切换到浅色模式',
        darkModeSwitchTitle: '切换到深色模式',
        footer: {
            message: '基于 MIT License 发布 · 源项目 7Sageer/sublink-worker',
            copyright: 'Sublink Worker'
        },
        locales: {
            en: {
                label: 'English',
                selectText: 'Languages',
                nav: [
                    { text: 'Guide', link: '/en/guide/getting-started' },
                    { text: 'Protocol Support', link: '/en/protocol-support' },
                    { text: 'Releases', link: `${repository}/releases` },
                    { text: 'GitHub', link: repository }
                ],
                sidebar: enSidebar,
                outline: { label: 'On this page', level: [2, 3] },
                docFooter: { prev: 'Previous', next: 'Next' },
                lastUpdated: { text: 'Last updated' },
                editLink: {
                    pattern: `${repository}/edit/main/docs/:path`,
                    text: 'Edit this page on GitHub'
                },
                returnToTopLabel: 'Return to top',
                sidebarMenuLabel: 'Menu',
                langMenuLabel: 'Change language',
                skipToContentLabel: 'Skip to content',
                darkModeSwitchLabel: 'Appearance',
                footer: {
                    message: 'Released under the MIT License · Originated from 7Sageer/sublink-worker',
                    copyright: 'Sublink Worker'
                }
            }
        }
    }
});
