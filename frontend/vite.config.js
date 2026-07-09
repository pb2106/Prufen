import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
    plugins: [
        react(),
        nodePolyfills({
            globals: {
                Buffer: true,
                global: true,
                process: true,
            },
        }),
    ],
    server: {
        host: '0.0.0.0',
        port: 5173,

        allowedHosts: [
            'localhost',
            '.trycloudflare.com',   // cloudflared
        ],

        // Only used in local dev — on Vercel, /api is routed via vercel.json's
        // services rewrite, so this proxy block is inert in production.
        proxy: {
            '/api': {
                target: 'http://localhost:8000',
                changeOrigin: true,
                configure: (proxy, options) => {
                    proxy.on('proxyReq', (proxyReq, req, res) => {
                        // Preserve Authorization header through proxy
                        if (req.headers.authorization) {
                            proxyReq.setHeader('Authorization', req.headers.authorization);
                        }
                    });
                }
            }
        }
    }
})